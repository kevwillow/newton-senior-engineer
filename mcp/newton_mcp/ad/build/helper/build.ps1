param(
    [string]$InstallRoot = '',
    [string]$KeyPath = '',
    [string]$StageTablePath = '',
    [string]$Now = '',
    [string]$BootTime = ''
)

# The build helper of Newton 1.5 (PLAN-1.5 task 3, DESIGN-1.5 "The
# helper", "The property", "Tokens", "Stage graphs", "Checkpoints" and
# "Deviation and resume").
#
# The helper runs on the Windows Server 2025 that becomes a domain
# controller, under Windows PowerShell 5.1, from the sshd ForceCommand.
# It reads one JSON request on stdin and writes one JSON object on
# stdout.  It exits 0 whatever the outcome.
#
# The request holds the canonical bytes of the approved plan (base64),
# the stage, the action, the token and the window of the token.  The
# helper recomputes the digest of those bytes, checks the token
# against it and reads every parameter of a stage out of them: nothing
# outside the bytes reaches a stage.
#
# THE STAGE TEMPLATES OF STAGES 0 TO 6 ARE IN THIS FILE (tasks 5 and 6).
# The templates of stages 7 to 10 are tasks 7 and 8: for those the stage
# table below is a placeholder, and the tests of task 3 drive every
# stage with a fake table of their own.
#
# THE OVERRIDES ARE FOR THE TESTS ONLY.  The install root, the path of
# the key, the stage table, the clock and the boot time may be named on
# the command line, and every one of them is refused when the session
# came over SSH.  The forced command of sshd runs the helper with no
# argument of the client: the command of the client goes to
# SSH_ORIGINAL_COMMAND and not into the arguments of the helper.  The
# refusal of the overrides is the defence in depth under that.

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$script:InstallRootOverride = $InstallRoot
$script:KeyPathOverride = $KeyPath
$script:StageTablePathOverride = $StageTablePath
$script:NowOverride = $Now
$script:BootTimeOverride = $BootTime

# The lock of the journal: set by Enter-NewtonJournalLock.  It is null
# until then, so a refusal raised before the lock still answers and
# exits 0 under StrictMode.
$script:JournalLock = $null

# The version of the helper.
$script:HelperVersion = '1.5.0'

# The install root of the helper.  The bootstrap of task 4 installs the
# helper here and the sshd forced command names this path.
$script:DefaultInstallRoot = 'C:\ProgramData\Newton\ad-build'

# The names of the files of the install.
$script:KeyFileName = 'key.hex'
$script:HelperFileName = 'build.ps1'
$script:DeviceFileName = 'device.txt'
$script:JournalDirectoryName = 'journal'
$script:JournalLockFileName = 'lock'

# The header line of the canonical plan document (DESIGN-1.5 "The plan").
$script:PlanHeader = 'newton-ad-build-v1'

# The header line of the message the stage digest is the hash of
# (DESIGN-1.5 "Tokens").
$script:StageHeader = 'newton-ad-build-stage-v1'

# The prefix of the message the approval token is the HMAC of
# (newton_mcp.approve.approval_token).
$script:TokenPrefix = 'newton-approval-v2'

# The biggest request the helper reads.  The request holds the whole
# canonical plan of the build, base64.
$script:MaxRequestBytes = 1048576

# The grace of the post-boot completion: a stage that reboots may be
# completed until the EXP of its token plus this many seconds
# (DESIGN-1.5 "The helper").
$script:PostBootGraceSeconds = 900

# The patterns of the request.
$script:RunPattern = '\A[0-9a-f]{32}\z'
$script:TokenPattern = '\A[0-9a-f]{64}\z'
$script:StagePattern = '\A(0|1|2|3|4|5|6|7|8|9|10)\z'
$script:ActionPattern = '\A(run|status|checkpoint|read)\z'
$script:DevicePattern = '\A[a-z][a-z0-9-]{0,31}\z'
$script:RolePattern = '\A(dc1|dc2)\z'
$script:KindPattern = '\A(read|reversible|irreversible|final)\z'
$script:KeyPattern = '\A[0-9a-f]{64}\z'
$script:CheckpointIdPattern = '\A[!-~]{1,128}\z'
# The DC reads of a checkpoint verify (PLAN-1.5 task 8 part B0): the
# msDS-GenerationId line, repadmin /showbackup and wbadmin get versions.
$script:ReadPattern = '\A(genid|showbackup|versions)\z'
$script:PlanKeyPattern = '\A[A-Za-z0-9._-]+\z'

# The bounds of the window of a token (newton_mcp.approve).
$script:EpochMin = 1000000000
$script:EpochMax = 9999999999

# The states of a journal entry.  The four of the design are the states
# of a stage; the fifth is the entry of a checkpoint, which holds the id
# of the checkpoint the token of the stage was minted over.
$script:StartedState = 'started'
$script:RebootingState = 'rebooting'
$script:DoneState = 'done'
$script:StoppedState = 'stopped'
$script:CheckpointedState = 'checkpointed'

# The phases of stage 7 (option B; the maintainer's decision K19, 2026-11-15): DC1's
# three runs (the provision, the install, the read-back) and DC2's join,
# its membership after the join's boot and its DC after the promotion's.
# A phase that ends in "ed" is the end of DC1's run of that name.
$script:ReplicaPhases = @('s7_provision', 's7_provisioned', 's7_install', 's7_installed', 's7_read',
    's7_join', 's7_member', 's7_dc')

# The reasons of a stopped stage (DESIGN-1.5 "Deviation and resume": the
# journal records stopped and the reason).  The one of the helper is
# the grace of a reboot that passed; the others are the deviations of
# the stage templates (task 5: stages 0 to 4; task 6: stages 5 and 6).  Stage 0's are the
# preconditions of the stage table; dns_unchecked is a DNS check that
# could not be made (no resolver, or a server failure: MEASURED-1.5).
$script:GracePassedReason = 'grace_passed'
$script:StoppedReasons = @(
    'grace_passed',
    'os_mismatch', 'not_workgroup', 'adds_present', 'ip_mismatch', 'clock_skew',
    'disk_low', 'domain_exists', 'dns_unchecked', 'agent_missing',
    'op_failed', 'readback_failed', 'directory_unready', 'generation_id_missing', 'error',
    'domain_mismatch', 'privileged_groups_remain')

# The kinds of a stage (DESIGN-1.5, the stage table).
$script:ReadKind = 'read'
$script:ReversibleKind = 'reversible'
$script:IrreversibleKind = 'irreversible'
$script:FinalKind = 'final'

# The kind of every stage and the graph of every role (DESIGN-1.5, the
# stage table and "Stage graphs").  The helper holds them: the kinds
# and the graphs of the signed bytes are the ones of the design, or the
# bytes are not the plan of the design and are refused.
$script:DesignStageKinds = @{
    '0' = 'read'
    '1' = 'reversible'
    '2' = 'irreversible'
    '3' = 'irreversible'
    '4' = 'irreversible'
    '5' = 'reversible'
    '6' = 'irreversible'
    '7' = 'irreversible'
    '8' = 'reversible'
    '9' = 'final'
    '10' = 'read'
}

# The graph of DC1 with a DC2 and the graph of DC1 alone: stage 7 is
# the replica DC, so it is in the graph only when the plan holds one.
$script:DesignGraphDc1 = '0,1,2,3,4,5,6,7,8,9,10'
$script:DesignGraphDc1Alone = '0,1,2,3,4,5,6,8,9,10'
$script:DesignGraphDc2 = '0,1,7,9'

# The states of the answer.
$script:AnswerPending = 'pending'
$script:AnswerStarted = 'started'
$script:AnswerRebooting = 'rebooting'
$script:AnswerDone = 'done'
$script:AnswerStopped = 'stopped'
$script:AnswerCheckpointed = 'checkpointed'
$script:AnswerRefused = 'refused'

# ---------------------------------------------------------------------------
# the small helpers
# ---------------------------------------------------------------------------

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

function Get-NewtonRefusalCode {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 'schema' }
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception.Data -and $exception.Data.Contains('NewtonCode')) {
            return [string]$exception.Data['NewtonCode']
        }
        $exception = $exception.InnerException
    }
    return 'schema'
}

function Test-NewtonIOException {
    # True when the error is the refusal of the operating system: the
    # file is there, or another writer holds it.
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return $false }
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception -is [System.IO.IOException]) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}

function Get-NewtonField {
    # The value of a property, by its exact name: a key that differs
    # only in case is a different key.
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
    if ($null -eq $Object) { return ,$names }
    foreach ($property in $Object.PSObject.Properties) { [void]$names.Add($property.Name) }
    return ,$names
}

function Get-NewtonText {
    # The text of a string field: the text the request wrote, never a
    # date the parser of PowerShell 7 made of it.  Windows PowerShell
    # 5.1 keeps every string as text, so the two agree.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [DateTime]) {
        return ([DateTime]$Value).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    return $null
}

function Get-NewtonBootText {
    # The boot time of a journal entry, as text.  The parser of
    # PowerShell 7 turns the date-like text of the boot time into a
    # date, so the value is read back as the text of that date.
    param($Object)
    $value = Get-NewtonField $Object 'boot'
    if ($null -eq $value) { return '' }
    if ($value -is [string]) { return $value }
    if ($value -is [DateTime]) {
        return ([DateTime]$value).ToUniversalTime().ToString(
            'o', [Globalization.CultureInfo]::InvariantCulture)
    }
    return ''
}

function Get-NewtonNow {
    # The clock of the helper.  The tests pin it.
    if (-not [string]::IsNullOrEmpty($script:NowOverride)) {
        $value = 0
        if (-not [int64]::TryParse($script:NowOverride, [ref]$value)) {
            Throw-NewtonRefusal 'schema' 'the clock of the helper is not a time'
        }
        return $value
    }
    return [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

function Get-NewtonBootTime {
    # The boot time of the server.  The tests pin it.  A server that
    # does not answer it has a boot time the helper cannot compare, and
    # a stage that waits for a reboot then waits for ever.
    if (-not [string]::IsNullOrEmpty($script:BootTimeOverride)) {
        $value = [DateTime]::MinValue
        $styles = [Globalization.DateTimeStyles]::RoundtripKind
        $culture = [Globalization.CultureInfo]::InvariantCulture
        if (-not [DateTime]::TryParse($script:BootTimeOverride, $culture, $styles, [ref]$value)) {
            Throw-NewtonRefusal 'schema' 'the boot time of the helper is not a time'
        }
        return $value.ToUniversalTime()
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return ([DateTime]$os.LastBootUpTime).ToUniversalTime()
    } catch {
        return [DateTime]::MinValue
    }
}

function Format-NewtonBootTime {
    # The boot time as it is written in the journal.
    param([DateTime]$Boot)
    if ($Boot -eq [DateTime]::MinValue) { return '' }
    return $Boot.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
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

function Get-NewtonPlanDigest {
    # The digest of the plan: the sha256 of its canonical bytes.
    param([byte[]]$Bytes)
    return (Get-NewtonSha256Hex $Bytes)
}

function Get-NewtonStageDigest {
    # The digest of one stage: the sha256 of the message of the design,
    # the header, then the plan, the stage and the checkpoint, each on
    # a line of its own.  The checkpoint is in the signed bytes, so a
    # token of a stage does not open another checkpoint.
    param([string]$PlanDigest, [string]$Stage, [string]$CheckpointId)
    $message = $script:StageHeader + "`n" +
        'plan=' + $PlanDigest + "`n" +
        'stage=' + $Stage + "`n" +
        'checkpoint=' + $CheckpointId + "`n"
    return (Get-NewtonSha256Hex ([System.Text.Encoding]::ASCII.GetBytes($message)))
}

function Get-NewtonToken {
    # HMAC-SHA256(K, "newton-approval-v2\n" + digest + "\n" + nbf + "\n"
    # + exp + "\n"): the token of newton_mcp.approve, byte for byte.
    param([byte[]]$Key, [string]$Digest, [int64]$NotBefore, [int64]$NotAfter)
    $culture = [Globalization.CultureInfo]::InvariantCulture
    $message = $script:TokenPrefix + "`n" +
        $Digest + "`n" +
        $NotBefore.ToString($culture) + "`n" +
        $NotAfter.ToString($culture) + "`n"
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

function New-NewtonAnswer {
    # The answer of the helper: {ok, status, code, checks}.
    param([bool]$Ok, [string]$Status, [string]$Code, $Checks)
    if ($null -eq $Checks) { $Checks = @() }
    return [ordered]@{ ok = $Ok; status = $Status; code = $Code; checks = @($Checks) }
}

# ---------------------------------------------------------------------------
# the install
# ---------------------------------------------------------------------------

function Get-NewtonInstallRoot {
    if (-not [string]::IsNullOrEmpty($script:InstallRootOverride)) {
        return $script:InstallRootOverride
    }
    return $script:DefaultInstallRoot
}

function Get-NewtonKeyPath {
    if (-not [string]::IsNullOrEmpty($script:KeyPathOverride)) { return $script:KeyPathOverride }
    return (Join-Path (Get-NewtonInstallRoot) $script:KeyFileName)
}

function Get-NewtonDevicePath {
    return (Join-Path (Get-NewtonInstallRoot) $script:DeviceFileName)
}

function Get-NewtonJournalDirectory {
    return (Join-Path (Get-NewtonInstallRoot) $script:JournalDirectoryName)
}

function Get-NewtonJournalPath {
    param([string]$Run, [int64]$Seq)
    return (Join-Path (Get-NewtonJournalDirectory) ($Run + '.' + [string]$Seq + '.json'))
}

function Enter-NewtonJournalLock {
    # The exclusive lock of the journal of the server: one request at a
    # time.  The lock is a file of the journal directory that no second
    # writer can open while the first one holds it, so two requests for
    # one stage do not run the stage twice.
    $directory = Get-NewtonJournalDirectory
    if (-not (Test-Path -LiteralPath $directory)) {
        try {
            $null = New-Item -ItemType Directory -Path $directory -Force
        } catch {
            Throw-NewtonRefusal 'schema' 'the journal of the server could not be opened'
        }
    }
    $path = Join-Path $directory $script:JournalLockFileName
    try {
        $script:JournalLock = [System.IO.File]::Open(
            $path,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
    } catch {
        if (Test-NewtonIOException $_) {
            # Another request holds the journal of the server: the lock is
            # taken, so this request waits and is told so (the lab run of
            # 2026-11-23: the helper of DC2 held the lock while its own
            # read-back ran).
            Throw-NewtonRefusal 'journal_busy' 'another request holds the journal of the server'
        }
        Throw-NewtonRefusal 'schema' 'the journal of the server could not be locked'
    }
}

function Exit-NewtonJournalLock {
    # The lock is held until the answer of the request is written.
    if ($null -eq $script:JournalLock) { return }
    try {
        $script:JournalLock.Close()
    } catch {
        # The lock is released by the operating system when the process
        # ends; a failure here changes nothing.
    }
    $script:JournalLock = $null
}

function Get-NewtonStageTablePath {
    # The path of the stage table.  There is none in the install root:
    # the stage templates are compiled into the helper, and a table of
    # the disk is the fake table of the tests, which is named on the
    # command line.
    if (-not [string]::IsNullOrEmpty($script:StageTablePathOverride)) {
        return $script:StageTablePathOverride
    }
    return ''
}

function Get-NewtonDeviceName {
    # The device name of this server: the plan holds it, and the
    # install of the helper names the server it is on.
    $path = Get-NewtonDevicePath
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    $text = ''
    try {
        $text = [System.IO.File]::ReadAllText($path)
    } catch {
        return ''
    }
    $name = $text.Trim()
    if ($name -cnotmatch $script:DevicePattern) { return '' }
    return $name
}

function Get-NewtonKeyBytes {
    # The key K of this server: 64 lowercase hexadecimal characters.
    $path = Get-NewtonKeyPath
    if (-not (Test-Path -LiteralPath $path)) {
        Throw-NewtonRefusal 'schema' 'the key of the server is not there'
    }
    $text = ''
    try {
        $text = [System.IO.File]::ReadAllText($path)
    } catch {
        Throw-NewtonRefusal 'schema' 'the key of the server could not be read'
    }
    $hex = $text.Trim()
    if ($hex -cnotmatch $script:KeyPattern) {
        Throw-NewtonRefusal 'schema' 'the key of the server is not a key'
    }
    $bytes = New-Object byte[] 32
    for ($index = 0; $index -lt 32; $index++) {
        $bytes[$index] = [System.Convert]::ToByte($hex.Substring($index * 2, 2), 16)
    }
    return ,$bytes
}

function Test-NewtonSshSession {
    # True when the session came over SSH.  sshd sets both of these
    # for every session it serves.
    if (-not [string]::IsNullOrEmpty($env:SSH_CONNECTION)) { return $true }
    if (-not [string]::IsNullOrEmpty($env:SSH_CLIENT)) { return $true }
    return $false
}

function Test-NewtonOverride {
    # True when the caller named an override.  An override is a way to
    # point the helper at another install, another key, another clock,
    # so it is refused when the session came over SSH.
    if (-not [string]::IsNullOrEmpty($script:InstallRootOverride)) { return $true }
    if (-not [string]::IsNullOrEmpty($script:KeyPathOverride)) { return $true }
    if (-not [string]::IsNullOrEmpty($script:StageTablePathOverride)) { return $true }
    if (-not [string]::IsNullOrEmpty($script:NowOverride)) { return $true }
    if (-not [string]::IsNullOrEmpty($script:BootTimeOverride)) { return $true }
    return $false
}

# ---------------------------------------------------------------------------
# the JSON scanner
#
# The scanner walks the raw text of the request before ConvertFrom-Json
# sees it, the way mcp/newton_mcp/ad/collector/write.ps1 does.  The
# JSON parser of PowerShell keeps the last of a key written twice, and
# the run of the request is not in the signed bytes: a second run key
# would pick the journal written to without a word.  So a duplicate key
# and two keys that differ only in case are refused.
# ---------------------------------------------------------------------------

$script:JsonText = ''
$script:JsonIndex = 0
$script:JsonLength = 0
$script:JsonString = ''
$script:JsonFail = $false
$script:JsonDepth = 0

# The deepest nesting the scanner accepts.  A request of the contract is
# a flat object; the scan of a deep text stays linear in its size.
$script:JsonDepthMax = 32

# The characters that end a run of plain characters of a string.
$script:JsonStringStops = [char[]]@([char]'"', [char]'\')

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
        # The run of plain characters up to the next quote or escape, in
        # one slice: the plan of the request is a long base64 string.
        $stop = $script:JsonText.IndexOfAny($script:JsonStringStops, $script:JsonIndex)
        if ($stop -lt 0) { $script:JsonFail = $true; return }
        $slice = $script:JsonText.Substring($script:JsonIndex, $stop - $script:JsonIndex)
        if ($slice -match '[\x00-\x1f]') { $script:JsonFail = $true; return }
        [void]$builder.Append($slice)
        $script:JsonIndex = $stop
    }
}

function Read-NewtonJsonNumber {
    # The number at the cursor, in the grammar of JSON.  Whether it is an
    # integer of the contract is checked on the parsed request.
    $script:JsonFail = $false
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
}

function Read-NewtonJsonValue {
    Skip-NewtonJsonSpace
    if ($script:JsonIndex -ge $script:JsonLength) { return $false }
    $character = $script:JsonText[$script:JsonIndex]
    if ($character -eq '{') { return (Read-NewtonJsonObject) }
    if ($character -eq '[') { return (Read-NewtonJsonArray) }
    if ($character -eq '"') {
        Read-NewtonJsonString
        return (-not $script:JsonFail)
    }
    if (($character -eq '-') -or ($character -match '[0-9]')) {
        Read-NewtonJsonNumber
        return (-not $script:JsonFail)
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
        # ArrayList.Contains makes this scan quadratic in the keys of
        # one object; MaxRequestBytes (1 MB) bounds the keys, so the
        # cost is bounded too.
        if ($keys.Contains($key)) { return $false }
        $lower = $key.ToLowerInvariant()
        if ($lowered.Contains($lower)) { return $false }
        [void]$keys.Add($key)
        [void]$lowered.Add($lower)
        Skip-NewtonJsonSpace
        if ($script:JsonIndex -ge $script:JsonLength) { return $false }
        if ($script:JsonText[$script:JsonIndex] -ne ':') { return $false }
        $script:JsonIndex = $script:JsonIndex + 1
        if (-not (Read-NewtonJsonValue)) { return $false }
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
    Skip-NewtonJsonSpace
    if (($script:JsonIndex -lt $script:JsonLength) -and ($script:JsonText[$script:JsonIndex] -eq ']')) {
        $script:JsonIndex = $script:JsonIndex + 1
        return $true
    }
    while ($true) {
        if (-not (Read-NewtonJsonValue)) { return $false }
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
    # The raw text of the request: one JSON object, no duplicate key and
    # no two keys that differ only in case, at any depth.
    param([string]$Text)
    $script:JsonText = $Text
    $script:JsonIndex = 0
    $script:JsonLength = $Text.Length
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

# ---------------------------------------------------------------------------
# the request
# ---------------------------------------------------------------------------

function Read-NewtonStdin {
    # The request on stdin.
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

function Test-NewtonInt {
    # True when the value is an integer of the request.
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($value -is [bool]) { return $false }
    if ($value -is [string]) { return $false }
    $code = [System.Type]::GetTypeCode($Value.GetType())
    if ($code -eq [System.TypeCode]::Int32) { return $true }
    if ($code -eq [System.TypeCode]::Int64) { return $true }
    return $false
}

function ConvertFrom-NewtonRequest {
    # One request, checked against the contract of the design.
    param([string]$Raw)
    if ($null -eq $Raw) { Throw-NewtonRefusal 'schema' 'the request is empty' }
    if ([System.Text.Encoding]::UTF8.GetByteCount($Raw) -gt $script:MaxRequestBytes) {
        Throw-NewtonRefusal 'schema' 'the request is too big'
    }
    if ([string]::IsNullOrEmpty($Raw.Trim())) {
        Throw-NewtonRefusal 'schema' 'the request is empty'
    }
    # The raw text first: a key written twice, or two keys that differ
    # only in case, is refused before the parser keeps the last one.
    if (-not (Test-NewtonJsonText -Text $Raw)) {
        Throw-NewtonRefusal 'schema' 'the request is not one JSON object with distinct keys'
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

    # The request holds exactly the fields of the contract.  A checkpoint
    # request may also name the id of a checkpoint Newton took through a
    # hypervisor adapter (PLAN-1.5 task 8; DESIGN-1.5, open point 9 of
    # task 7); no other request names one.
    $expected = @('run', 'plan', 'stage', 'action', 'token', 'nbf', 'exp')
    $names = Get-NewtonFieldNames $parsed
    $namesCheckpoint = $false
    foreach ($candidate in $names) {
        if ($candidate -ceq 'checkpoint') { $namesCheckpoint = $true; break }
    }
    if ($namesCheckpoint) { $expected = $expected + @('checkpoint') }
    # A request that names a checkpoint may also name its name (the
    # hypervisor's name of it), which the journal keeps beside the id so a
    # runner started again verifies that checkpoint instead of taking a
    # second one (F1 of the part C triage of task 8).
    $namesCheckpointName = $false
    foreach ($candidate in $names) {
        if ($candidate -ceq 'checkpoint_name') { $namesCheckpointName = $true; break }
    }
    if ($namesCheckpointName) { $expected = $expected + @('checkpoint_name') }
    # A read request names its read (genid, showbackup or versions) in
    # an eighth field, and no other request names one.
    $namesRead = $false
    foreach ($candidate in $names) {
        if ($candidate -ceq 'read') { $namesRead = $true; break }
    }
    if ($namesRead) { $expected = $expected + @('read') }
    # DC2's stage 7 run carries the offline domain join blob DC1's
    # provision answered (option B), and no other request carries one.
    $namesOdj = $false
    foreach ($candidate in $names) {
        if ($candidate -ceq 'odj') { $namesOdj = $true; break }
    }
    if ($namesOdj) { $expected = $expected + @('odj') }
    # No request carries the 1.4 write helper: the bootstrap installed it
    # (the maintainer's decision of 2026-11-19 on the stage 8 transport), so a request
    # that names the field holds a field outside the contract.
    if ($names.Count -ne $expected.Count) {
        Throw-NewtonRefusal 'schema' 'the request does not hold the fields of a request'
    }
    foreach ($name in $expected) {
        $found = $false
        foreach ($candidate in $names) {
            if ($candidate -ceq $name) { $found = $true; break }
        }
        if (-not $found) {
            Throw-NewtonRefusal 'schema' 'the request does not hold the fields of a request'
        }
    }

    $request = @{}

    $run = Get-NewtonText (Get-NewtonField $parsed 'run')
    if (($run -isnot [string]) -or ($run -cnotmatch $script:RunPattern)) {
        Throw-NewtonRefusal 'schema' 'the run is outside its pattern'
    }
    $request['run'] = $run

    $encoded = Get-NewtonText (Get-NewtonField $parsed 'plan')
    if (($encoded -isnot [string]) -or ([string]::IsNullOrEmpty($encoded))) {
        Throw-NewtonRefusal 'schema' 'the plan of the request is not text'
    }
    $bytes = $null
    try {
        $bytes = [System.Convert]::FromBase64String($encoded)
    } catch {
        Throw-NewtonRefusal 'schema' 'the plan of the request is not base64'
    }
    $request['plan_bytes'] = $bytes

    $stage = Get-NewtonText (Get-NewtonField $parsed 'stage')
    if (($stage -isnot [string]) -or ($stage -cnotmatch $script:StagePattern)) {
        Throw-NewtonRefusal 'schema' 'the stage is outside its pattern'
    }
    $request['stage'] = $stage

    $action = Get-NewtonText (Get-NewtonField $parsed 'action')
    if (($action -isnot [string]) -or ($action -cnotmatch $script:ActionPattern)) {
        Throw-NewtonRefusal 'schema' 'the action is not one of the actions'
    }
    $request['action'] = $action

    if ($namesCheckpoint) {
        if ($action -cne 'checkpoint') {
            Throw-NewtonRefusal 'schema' 'only a checkpoint request names a checkpoint'
        }
        $named = Get-NewtonText (Get-NewtonField $parsed 'checkpoint')
        if (($named -isnot [string]) -or ($named -cnotmatch $script:CheckpointIdPattern)) {
            Throw-NewtonRefusal 'schema' 'the checkpoint of the request is outside its grammar'
        }
        $request['checkpoint_id'] = $named
    }
    if ($namesCheckpointName) {
        if (-not $namesCheckpoint) {
            Throw-NewtonRefusal 'schema' 'only a request that names a checkpoint names its name'
        }
        $checkpointName = Get-NewtonText (Get-NewtonField $parsed 'checkpoint_name')
        if (($checkpointName -isnot [string]) -or ($checkpointName -cnotmatch $script:CheckpointIdPattern)) {
            Throw-NewtonRefusal 'schema' 'the checkpoint name of the request is outside its grammar'
        }
        $request['checkpoint_name'] = $checkpointName
    }
    if ($namesOdj) {
        if (($action -cne 'run') -or ($stage -cne $script:ReplicaStage)) {
            Throw-NewtonRefusal 'schema' 'only a stage 7 run request carries the offline domain join blob'
        }
        $odjText = Get-NewtonText (Get-NewtonField $parsed 'odj')
        if (($odjText -isnot [string]) -or ($odjText.Length -lt 4) -or ($odjText.Length -gt $script:OdjMaxChars) -or
            ($odjText -cnotmatch $script:OdjPattern)) {
            Throw-NewtonRefusal 'schema' 'the offline domain join blob is outside its grammar'
        }
        $request['odj_bytes'] = [System.Convert]::FromBase64String($odjText)
    }
    if ($namesRead -or ($action -ceq 'read')) {
        if ($action -cne 'read') {
            Throw-NewtonRefusal 'schema' 'only a read request names a read'
        }
        if (-not $namesRead) {
            Throw-NewtonRefusal 'schema' 'a read request names its read'
        }
        if ($namesCheckpoint) {
            Throw-NewtonRefusal 'schema' 'a read request names no checkpoint'
        }
        # Read in place, not through a function: a function would unroll
        # a one-element array into the string it holds.
        $read = $null
        foreach ($property in $parsed.PSObject.Properties) {
            if ($property.Name -ceq 'read') { $read = $property.Value }
        }
        if (($read -isnot [string]) -or ($read -cnotmatch $script:ReadPattern)) {
            Throw-NewtonRefusal 'schema' 'the read of the request is not one of the reads'
        }
        $request['read'] = $read
    }

    $token = Get-NewtonText (Get-NewtonField $parsed 'token')
    if (($token -isnot [string]) -or ($token -cnotmatch $script:TokenPattern)) {
        Throw-NewtonRefusal 'schema' 'the token is outside its pattern'
    }
    $request['token'] = $token

    foreach ($name in @('nbf', 'exp')) {
        $value = Get-NewtonField $parsed $name
        if (-not (Test-NewtonInt $value)) {
            Throw-NewtonRefusal 'schema' ('the approval ' + $name + ' is not an integer')
        }
        $number = [int64]$value
        if (($number -lt $script:EpochMin) -or ($number -gt $script:EpochMax)) {
            Throw-NewtonRefusal 'schema' ('the approval ' + $name + ' is outside the range of the helper')
        }
        $request[$name] = $number
    }
    if ($request['exp'] -le $request['nbf']) {
        Throw-NewtonRefusal 'schema' 'the approval window does not move forward'
    }

    return $request
}

# ---------------------------------------------------------------------------
# the plan
# ---------------------------------------------------------------------------

function ConvertFrom-NewtonPlanBytes {
    # The pairs of the canonical plan document.  The document is ASCII,
    # one key=value pair per line, LF only, and its first line is the
    # header of the plan.
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        Throw-NewtonRefusal 'schema' 'the plan of the request is empty'
    }
    foreach ($byte in $Bytes) {
        if ($byte -gt 127) {
            Throw-NewtonRefusal 'schema' 'the plan of the request is not ASCII'
        }
    }
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
    if ($text.Contains("`r")) {
        Throw-NewtonRefusal 'schema' 'the plan of the request holds a carriage return'
    }
    if (-not $text.EndsWith("`n")) {
        Throw-NewtonRefusal 'schema' 'the plan of the request does not end with a line feed'
    }
    $lines = $text.Split(@("`n"), [System.StringSplitOptions]::None)
    if ($lines[0] -cne $script:PlanHeader) {
        Throw-NewtonRefusal 'schema' 'the plan of the request does not hold the header of the plan'
    }
    $pairs = @{}
    for ($index = 1; $index -lt ($lines.Length - 1); $index++) {
        $line = $lines[$index]
        if ([string]::IsNullOrEmpty($line)) {
            Throw-NewtonRefusal 'schema' 'the plan of the request holds an empty line'
        }
        $split = $line.IndexOf('=')
        if ($split -le 0) {
            Throw-NewtonRefusal 'schema' 'a line of the plan of the request is not a pair'
        }
        $key = $line.Substring(0, $split)
        if ($key -cnotmatch $script:PlanKeyPattern) {
            Throw-NewtonRefusal 'schema' 'a key of the plan of the request is outside its grammar'
        }
        if ($pairs.ContainsKey($key)) {
            Throw-NewtonRefusal 'schema' 'the plan of the request holds a key twice'
        }
        $pairs[$key] = $line.Substring($split + 1)
    }
    return $pairs
}

function Get-NewtonPlanRole {
    # The role of this server, out of the plan: the plan holds the
    # device name of every server and the role of it.
    param([hashtable]$Plan, [string]$Device)
    $index = 0
    while ($Plan.ContainsKey('servers.' + [string]$index + '.device')) {
        if ([string]$Plan['servers.' + [string]$index + '.device'] -ceq $Device) {
            $role = [string]$Plan['servers.' + [string]$index + '.role']
            if ($role -cnotmatch $script:RolePattern) {
                Throw-NewtonRefusal 'schema' 'the role of this server is outside its grammar'
            }
            return $role
        }
        $index = $index + 1
    }
    Throw-NewtonRefusal 'schema' 'this server is not in the plan of the request'
}

function Get-NewtonPlanGraph {
    # The stage graph of this server, out of the plan.
    param([hashtable]$Plan, [string]$Role)
    $key = 'stages.graph.' + $Role
    if (-not $Plan.ContainsKey($key)) {
        Throw-NewtonRefusal 'schema' 'the plan of the request holds no graph for this server'
    }
    $stages = New-Object System.Collections.ArrayList
    foreach ($part in ([string]$Plan[$key]).Split(',')) {
        if ($part -cnotmatch $script:StagePattern) {
            Throw-NewtonRefusal 'schema' 'the graph of this server holds a stage outside its grammar'
        }
        [void]$stages.Add($part)
    }
    return ,$stages.ToArray()
}

function Get-NewtonPlanKind {
    # The kind of one stage, out of the plan.
    param([hashtable]$Plan, [string]$Stage)
    $key = 'stages.kind.' + $Stage
    if (-not $Plan.ContainsKey($key)) {
        Throw-NewtonRefusal 'schema' 'the plan of the request holds no kind for that stage'
    }
    $kind = [string]$Plan[$key]
    if ($kind -cnotmatch $script:KindPattern) {
        Throw-NewtonRefusal 'schema' 'the kind of the stage is outside its grammar'
    }
    return $kind
}

function Get-NewtonDesignKind {
    # The kind of one stage, out of the table of the design.
    param([string]$Stage)
    if (-not $script:DesignStageKinds.ContainsKey($Stage)) {
        Throw-NewtonRefusal 'schema' 'the stage is not one of the stages of the design'
    }
    return [string]$script:DesignStageKinds[$Stage]
}

function Get-NewtonPlanRoles {
    # Every role of the plan: the plan holds the role of every server.
    param([hashtable]$Plan)
    $roles = New-Object System.Collections.ArrayList
    $index = 0
    while ($Plan.ContainsKey('servers.' + [string]$index + '.role')) {
        $role = [string]$Plan['servers.' + [string]$index + '.role']
        if ($role -cnotmatch $script:RolePattern) {
            Throw-NewtonRefusal 'schema' 'the role of a server of the plan is outside its grammar'
        }
        [void]$roles.Add($role)
        $index = $index + 1
    }
    return ,$roles.ToArray()
}

function Assert-NewtonPlanDomainLevel {
    # The domain functional level of the plan.  The design builds the
    # forest at 2025 only, and the Windows LAPS policy of the baseline
    # (ADPasswordEncryptionEnabled) needs the domain functional level
    # 2016 or later, so a plan with a level below that is refused, and
    # the refusal names the policy and the level it needs.  A level of
    # 2016 or later that the design does not build is outside the
    # grammar of the level.
    param([hashtable]$Plan)
    $level = [string]$Plan['domain.functional_level']
    if (-not $script:DomainLevels.ContainsKey($level)) {
        Throw-NewtonRefusal 'schema' 'the plan value domain.functional_level is outside its grammar'
    }
    $number = [int]$script:DomainLevels[$level]
    if ($number -lt $script:LapsMinimumDomainLevel) {
        Throw-NewtonRefusal 'schema' ('the Windows LAPS policy of the domain controllers needs the domain functional level 2016 or later; the plan asks for ' + $level + ' (level ' + [string]$number + ')')
    }
    if (-not $script:LevelNames.ContainsKey($level)) {
        Throw-NewtonRefusal 'schema' 'the plan value domain.functional_level is outside its grammar'
    }
}

function Test-NewtonDesignPlan {
    # The plan of the request against the table of the design: the kind
    # of every stage and the graph of every role are the ones of the
    # design.  The signed bytes cannot relabel an irreversible stage as
    # a reversible one, and cannot take a stage out of the graph.
    param([hashtable]$Plan)

    # The domain functional level of the plan: the one the design builds
    # at, and the one the Windows LAPS policy of the baseline needs.
    Assert-NewtonPlanDomainLevel -Plan $Plan

    foreach ($stage in $script:DesignStageKinds.Keys) {
        $kind = Get-NewtonPlanKind -Plan $Plan -Stage ([string]$stage)
        if ($kind -cne [string]$script:DesignStageKinds[[string]$stage]) {
            Throw-NewtonRefusal 'schema' 'the kind of a stage of the plan is not the kind of the design'
        }
    }
    foreach ($key in $Plan.Keys) {
        if ($key -cnotlike 'stages.kind.*') { continue }
        $stage = $key.Substring('stages.kind.'.Length)
        if (-not $script:DesignStageKinds.ContainsKey($stage)) {
            Throw-NewtonRefusal 'schema' 'the plan of the request holds a kind of a stage of no design'
        }
    }

    $roles = Get-NewtonPlanRoles $Plan
    $hasDc2 = $false
    foreach ($role in $roles) {
        if ($role -ceq 'dc2') { $hasDc2 = $true }
    }
    foreach ($role in $roles) {
        $expected = $script:DesignGraphDc2
        if ($role -ceq 'dc1') {
            if ($hasDc2) { $expected = $script:DesignGraphDc1 } else { $expected = $script:DesignGraphDc1Alone }
        }
        $key = 'stages.graph.' + [string]$role
        if (-not $Plan.ContainsKey($key)) {
            Throw-NewtonRefusal 'schema' 'the plan of the request holds no graph for a server of the design'
        }
        if ([string]$Plan[$key] -cne [string]$expected) {
            Throw-NewtonRefusal 'schema' 'the graph of a server of the plan is not the graph of the design'
        }
    }
    foreach ($key in $Plan.Keys) {
        if ($key -cnotlike 'stages.graph.*') { continue }
        $role = $key.Substring('stages.graph.'.Length)
        $known = $false
        foreach ($one in $roles) {
            if ($one -ceq $role) { $known = $true }
        }
        if (-not $known) {
            Throw-NewtonRefusal 'schema' 'the plan of the request holds a graph of a role of no design'
        }
    }
}

# ---------------------------------------------------------------------------
# the journal
# ---------------------------------------------------------------------------

function Get-NewtonJournalEntries {
    # Every entry of the journal of the server, in the order of the seq.
    # The journal of a server holds one run, so every entry is read and
    # the run it belongs to is kept: an entry of another run is a
    # second build and the request is refused.
    param([string]$Run)
    $entries = New-Object System.Collections.ArrayList
    $directory = Get-NewtonJournalDirectory
    if (-not (Test-Path -LiteralPath $directory)) { return ,$entries.ToArray() }
    $files = @()
    try {
        $files = @(Get-ChildItem -LiteralPath $directory -File -ErrorAction SilentlyContinue)
    } catch {
        return ,$entries.ToArray()
    }
    $pattern = '\A([0-9a-f]{32})\.([0-9]+)\.json\z'
    foreach ($file in $files) {
        if (-not $file.Name.EndsWith('.json', [System.StringComparison]::Ordinal)) { continue }
        $runOfEntry = ''
        $seqText = ''
        if ($file.Name -cmatch $pattern) {
            $runOfEntry = $Matches[1]
            $seqText = $Matches[2]
        }
        if ([string]::IsNullOrEmpty($runOfEntry)) {
            # A file of the journal that is not named <run>.<seq>.json is
            # not an entry of any run: it is skipped, so it neither joins
            # the run nor refuses every later request as a second run.
            continue
        }
        $seq = 0
        if (-not [int64]::TryParse($seqText, [ref]$seq)) { continue }
        $text = ''
        try {
            $text = [System.IO.File]::ReadAllText($file.FullName)
        } catch {
            Throw-NewtonRefusal 'schema' 'a journal entry could not be read'
        }
        $record = $null
        try {
            $record = ConvertFrom-Json -InputObject $text
        } catch {
            Throw-NewtonRefusal 'schema' 'a journal entry is not JSON'
        }
        if ($null -eq $record) {
            Throw-NewtonRefusal 'schema' 'a journal entry is not JSON'
        }
        [void]$entries.Add(@{ seq = $seq; path = [string]$file.FullName; record = $record; run = $runOfEntry })
    }
    $sorted = @($entries | Sort-Object -Property @{ Expression = { $_.seq } })
    return ,$sorted
}

function Get-NewtonNextSeq {
    # The seq of the next entry of the journal of one run: strictly
    # increasing, and the first one is zero.
    param([string]$Run)
    $next = 0
    foreach ($entry in (Get-NewtonJournalEntries $Run)) {
        if ([string]$entry['run'] -cne $Run) { continue }
        if ([int64]$entry['seq'] -ge $next) { $next = [int64]$entry['seq'] + 1 }
    }
    return $next
}

function Write-NewtonJournalFile {
    # Every entry is a new file.  CreateNew is the append-only store's
    # refusal boundary: a collision never overwrites the other writer.
    #
    # The bytes of the entry are on the disk before the write that
    # guards it: Flush($true) asks for the flush of the file itself and
    # not only of the buffer of the process, and an entry that is in
    # the buffer of the process is an entry that a power cut loses.
    param([string]$Path, $Record)
    $json = $Record | ConvertTo-Json -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $directory = Get-NewtonJournalDirectory
    if (-not (Test-Path -LiteralPath $directory)) {
        try {
            $null = New-Item -ItemType Directory -Path $directory -Force
        } catch {
            Throw-NewtonRefusal 'schema' 'the journal of the run could not be opened'
        }
    }
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Close()
    }
}

function Add-NewtonJournalEntry {
    # One entry of the journal of one run.  The seq of the entry is the
    # next one; the journal is append-only, so a file that is already
    # there is a refusal and not a retry at the next seq: the request
    # holds the lock of the journal, and nothing else writes there.
    #
    # Every entry holds a reason: it is empty unless the stage was
    # stopped, and the reason of a stopped stage is one of the reasons
    # of the design.
    param([string]$Run, [int64]$Seq, [string]$Stage, [string]$State,
        [string]$Reason, [string]$Digest, [string]$Checkpoint, [string]$Boot, $Checks,
        [string]$Phase = '', [string]$CheckpointName = '')
    if ($null -eq $Checks) { $Checks = @() }
    if ($State -eq $script:StoppedState) {
        if ($Reason -notin $script:StoppedReasons) {
            Throw-NewtonRefusal 'schema' 'the reason of a stopped stage is not one of the reasons'
        }
    } elseif (-not [string]::IsNullOrEmpty($Reason)) {
        Throw-NewtonRefusal 'schema' 'only a stopped stage holds a reason'
    }
    $record = [ordered]@{
        run = $Run
        seq = $Seq
        stage = $Stage
        state = $State
        reason = $Reason
        digest = $Digest
        checkpoint = $Checkpoint
        boot = $Boot
        time = (Get-NewtonNow)
        checks = @($Checks)
    }
    # The salt of the run's secrets (open point 71): a later resume plan
    # must name the same.
    if (-not [string]::IsNullOrEmpty([string]$script:SecretsDigest)) { $record['secrets'] = [string]$script:SecretsDigest }
    # The phase of a stage 7 entry (the maintainer's decision K19, 2026-11-15: DC1's
    # three runs follow the phase its own journal records) and the name of
    # a checkpoint; neither is in the entries of the other stages.
    if (-not [string]::IsNullOrEmpty($Phase)) {
        if (($Phase -cnotin $script:ReplicaPhases) -and ($Phase -cnotin $script:OpsPhases)) {
            Throw-NewtonRefusal 'schema' 'the phase of the entry is not a phase of stage 7 or 8'
        }
        $record['phase'] = $Phase
    }
    if (-not [string]::IsNullOrEmpty($CheckpointName)) { $record['checkpoint_name'] = $CheckpointName }
    $path = Get-NewtonJournalPath -Run $Run -Seq $Seq
    try {
        Write-NewtonJournalFile -Path $path -Record $record
    } catch {
        if (Test-NewtonIOException $_) {
            Throw-NewtonRefusal 'schema' 'the journal of the run already holds that entry'
        }
        throw
    }
    return $record
}

function Get-NewtonStageState {
    # The state of one stage in the journal: the last entry of the stage
    # that is not the entry of a checkpoint.
    param($Entries, [string]$Stage)
    $state = ''
    $record = $null
    foreach ($entry in $Entries) {
        $one = $entry['record']
        if ([string](Get-NewtonField $one 'stage') -cne $Stage) { continue }
        $oneState = [string](Get-NewtonField $one 'state')
        if ($oneState -eq $script:CheckpointedState) { continue }
        $state = $oneState
        $record = $one
    }
    return @{ state = $state; record = $record }
}

function Get-NewtonNextStage {
    # The stage the run may do next: the first stage of the graph that
    # is not done.
    param([string[]]$Graph, $Entries)
    foreach ($stage in $Graph) {
        $info = Get-NewtonStageState -Entries $Entries -Stage $stage
        if ([string]$info['state'] -ne $script:DoneState) { return $stage }
    }
    return ''
}

function Get-NewtonCheckpointId {
    # The id of the checkpoint of one stage: the newest checkpointed
    # entry of that stage and of that plan.  A checkpoint of another
    # stage does not void the token of this one.
    param($Entries, [string]$Stage, [string]$Digest)
    $id = ''
    foreach ($entry in $Entries) {
        $one = $entry['record']
        if ([string](Get-NewtonField $one 'state') -ne $script:CheckpointedState) { continue }
        if ([string](Get-NewtonField $one 'stage') -cne $Stage) { continue }
        if ([string](Get-NewtonField $one 'digest') -cne $Digest) { continue }
        $id = [string](Get-NewtonField $one 'checkpoint')
    }
    if ([string]::IsNullOrEmpty($id)) { return '' }
    if ($id -cnotmatch $script:CheckpointIdPattern) { return '' }
    return $id
}

function Get-NewtonHeldCheckpoints {
    # Each stage's checkpoint of the plan of this digest, as a status
    # answers it: the newest checkpointed entry of the stage and the plan,
    # its id and the name the request named.
    param($Entries, [string[]]$Graph, [string]$Digest)
    $held = [ordered]@{}
    foreach ($stage in $Graph) {
        $id = Get-NewtonCheckpointId -Entries $Entries -Stage $stage -Digest $Digest
        if ([string]::IsNullOrEmpty($id)) { continue }
        $name = ''
        foreach ($entry in $Entries) {
            $one = $entry['record']
            if ([string](Get-NewtonField $one 'state') -ne $script:CheckpointedState) { continue }
            if ([string](Get-NewtonField $one 'stage') -cne $stage) { continue }
            if ([string](Get-NewtonField $one 'digest') -cne $Digest) { continue }
            $name = [string](Get-NewtonField $one 'checkpoint_name')
        }
        # A checkpoint recorded without a name (a request that named none)
        # is not answered: the runner cannot verify it again, takes a new
        # one, and the helper refuses that one out_of_order (fail closed).
        if ($name -cnotmatch $script:CheckpointIdPattern) { continue }
        $held[$stage] = [ordered]@{ id = $id; name = $name }
    }
    return $held
}

function Get-NewtonJournalDigest {
    # The digest of the plan the run was made with: the digest of the
    # last entry of a stage in the journal.  The entry of a checkpoint
    # is not an entry of a stage: a resume plan takes its checkpoint
    # before it runs its stage, and that checkpoint does not make the
    # resume plan the plan of the run.
    param($Entries)
    $digest = ''
    foreach ($entry in $Entries) {
        $one = $entry['record']
        if ([string](Get-NewtonField $one 'state') -eq $script:CheckpointedState) { continue }
        $value = [string](Get-NewtonField $one 'digest')
        if ($value -ceq '') { continue }
        $digest = $value
    }
    return $digest
}

function Get-NewtonJournalSecrets {
    # The salt of the derived secrets of the run (DESIGN-1.5 open point 71):
    # the secrets field of the last entry of a stage, or its digest when it
    # has none (an entry written before the field, whose plan's own digest
    # was the salt).  Checkpoint entries are skipped as in
    # Get-NewtonJournalDigest.
    param($Entries)
    $salt = ''
    foreach ($entry in $Entries) {
        $one = $entry['record']
        if ([string](Get-NewtonField $one 'state') -eq $script:CheckpointedState) { continue }
        $value = [string](Get-NewtonField $one 'digest')
        if ($value -ceq '') { continue }
        $recorded = [string](Get-NewtonField $one 'secrets')
        if ($recorded -cne '') { $value = $recorded }
        $salt = $value
    }
    return $salt
}

function Get-NewtonSecretsDigest {
    # The salt of the DSRM and the admin secret of the plan of the request
    # (DESIGN-1.5 "Secrets", open point 71): the plan digest of a first
    # plan; the signed secrets_from of a resume plan, the digest of the
    # build's first plan, so a resume plan derives the passwords the first
    # plan installed and newton-approve showed.  A resume plan carries it
    # and only a resume plan does; it is a digest.
    param([hashtable]$Plan, [string]$Digest)
    $hasResume = $Plan.ContainsKey('resume_from')
    $hasSecrets = $Plan.ContainsKey('secrets_from')
    if ($hasResume -ne $hasSecrets) {
        Throw-NewtonRefusal 'schema' 'a resume plan carries secrets_from, and only a resume plan'
    }
    if (-not $hasSecrets) { return $Digest }
    $value = [string]$Plan['secrets_from']
    if ($value -cnotmatch '\A[0-9a-f]{64}\z') {
        Throw-NewtonRefusal 'schema' 'the secrets_from of the plan is not a digest'
    }
    return $value
}

function Get-NewtonRequestSecrets {
    # The salt of this request, set once the plan bytes are read; a secret
    # is never derived without it.
    if ([string]::IsNullOrEmpty([string]$script:SecretsDigest)) {
        Throw-NewtonRefusal 'schema' 'the salt of the secrets of the plan is not known'
    }
    return [string]$script:SecretsDigest
}

function Assert-NewtonPlanOfRun {
    # The plan of the request against the plan of the run: the digest of
    # the journal, unless the plan resumes the run (its resume_from is
    # the digest of the journal and its start_stage the next stage).
    # It reads the journal and the plan and writes nothing.
    param([hashtable]$Plan, [string]$Digest, [string[]]$Graph, $Entries)
    $journalDigest = Get-NewtonJournalDigest $Entries
    if ([string]::IsNullOrEmpty($journalDigest) -or ($journalDigest -ceq $Digest)) { return }
    $resumeFrom = ''
    if ($Plan.ContainsKey('resume_from')) { $resumeFrom = [string]$Plan['resume_from'] }
    $startStage = ''
    if ($Plan.ContainsKey('start_stage')) { $startStage = [string]$Plan['start_stage'] }
    $next = Get-NewtonNextStage -Graph $Graph -Entries $Entries
    if (($resumeFrom -cne $journalDigest) -or ($startStage -cne $next)) {
        Throw-NewtonRefusal 'plan_mismatch' 'the plan of the request is not the plan of the run'
    }
    # A resume keeps the salt of the run's secrets: the DSRM and the admin
    # password the run installed are the ones its approvals show.
    if ((Get-NewtonSecretsDigest -Plan $Plan -Digest $Digest) -cne (Get-NewtonJournalSecrets $Entries)) {
        Throw-NewtonRefusal 'plan_mismatch' 'the resume plan does not keep the secrets of the run (its secrets_from)'
    }
    # A resume starts a stage that does not wait for a reboot: a stage
    # that waits for a reboot under the plan of the run is not started
    # again, and the run of the plan it waits for is not touched (it has
    # its own grace path).  A stage left started with no terminal entry
    # is resumed, or nothing ever could.
    $stateOfStart = Get-NewtonStageState -Entries $Entries -Stage $startStage
    $startState = [string]$stateOfStart['state']
    if (($startState -ne '') -and ($startState -ne $script:StoppedState) -and
        ($startState -ne $script:StartedState)) {
        Throw-NewtonRefusal 'out_of_order' 'the stage the plan resumes is in flight'
    }
}

# ---------------------------------------------------------------------------
# the stage table
# ---------------------------------------------------------------------------

function Get-NewtonBuiltInStageTable {
    # The table of the stages, without the templates: the placeholder
    # for the stage templates of tasks 5 to 8.
    $table = @{}
    foreach ($stage in @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10')) {
        $reboot = $false
        if (($stage -eq '1') -or ($stage -eq '2') -or ($stage -eq '7')) { $reboot = $true }
        $table[$stage] = @{ reboot = $reboot; drop = $false; checks = @() }
    }
    return $table
}

function ConvertTo-NewtonChecks {
    # The checks of a stage, as the answer and the journal hold them.
    param($Checks)
    $list = New-Object System.Collections.ArrayList
    if ($null -eq $Checks) { return ,$list.ToArray() }
    foreach ($check in $Checks) {
        $name = [string](Get-NewtonField $check 'name')
        if ([string]::IsNullOrEmpty($name)) { continue }
        $ok = Get-NewtonField $check 'ok'
        if ($ok -isnot [bool]) { $ok = $false }
        $detail = [string](Get-NewtonField $check 'detail')
        [void]$list.Add(@{ name = $name; ok = $ok; detail = $detail })
    }
    return ,$list.ToArray()
}

function Get-NewtonStageTable {
    # The table of the stages of this server.
    $path = Get-NewtonStageTablePath
    if ([string]::IsNullOrEmpty($path)) { return (Get-NewtonBuiltInStageTable) }
    $text = ''
    try {
        $text = [System.IO.File]::ReadAllText($path)
    } catch {
        Throw-NewtonRefusal 'schema' 'the stage table could not be read'
    }
    $parsed = $null
    try {
        $parsed = ConvertFrom-Json -InputObject $text
    } catch {
        Throw-NewtonRefusal 'schema' 'the stage table is not JSON'
    }
    $table = @{}
    foreach ($property in $parsed.PSObject.Properties) {
        $stage = $property.Name
        if ($stage -cnotmatch $script:StagePattern) {
            Throw-NewtonRefusal 'schema' 'the stage table holds a stage outside its grammar'
        }
        $one = $property.Value
        $reboot = Get-NewtonField $one 'reboot'
        if ($reboot -isnot [bool]) { $reboot = $false }
        $drop = Get-NewtonField $one 'drop'
        if ($drop -isnot [bool]) { $drop = $false }
        $table[$stage] = @{
            reboot = $reboot
            drop = $drop
            checks = (ConvertTo-NewtonChecks (Get-NewtonField $one 'checks'))
        }
    }
    return $table
}

function Get-NewtonStageEntry {
    # The entry of one stage of the table.
    param([hashtable]$Table, [string]$Stage)
    if (-not $Table.ContainsKey($Stage)) {
        return @{ reboot = $false; drop = $false; checks = @() }
    }
    return $Table[$Stage]
}

# ---------------------------------------------------------------------------
# the stage templates: stages 0 to 4 (PLAN-1.5 task 5) and 5 and 6 (task 6)
#
# A stage renders one or more ops.  An op is a PowerShell script the
# helper writes under the build directory and runs: in its own session
# for stages 0 and 1, before the promotion, and in the one-shot task
# registered with the password of newton-build for every op from the
# promotion on (DESIGN-1.5 "The build account after promotion";
# MEASURED-1.5 "Stages 0 to 4 on BUILD1, 2026-11-13").  The op writes
# its own output to the out directory, and the helper reads that output
# back into the checks of the stage.
#
# Every value of an op comes out of the plan bytes through
# Get-NewtonStageValues, which checks it against its grammar, and
# reaches the op only as a single-quoted literal assigned at the top
# of the op: the body of an op is constant text.  The lines an op
# prints are the lines of the measurement scripts, so the parsers read
# the shapes the measured server printed.
# ---------------------------------------------------------------------------

# The build directory of the bootstrap (bootstrap.BUILD_DIR): pw.bin,
# the ops, their output and the DPAPI file of the DSRM secret.
$script:BuildDir = 'C:\NewtonBuild'

# The build account (bootstrap.BUILD_USER).
$script:BuildUser = 'newton-build'

# The stages that have templates in this helper.  Stage 7 runs its own
# sequence (Invoke-NewtonReplicaRun) and stage 8 its own
# (Invoke-NewtonOpsRun); stage 10 is the runner's, through newton-audit.
$script:TemplateStages = @('0', '1', '2', '3', '4', '5', '6', '8', '9')

# Stage 7 (option B): the blob's files on DC1 (djoin /provision saves it
# there) and on DC2 (the join's run writes it from the request), its bound
# (ODJ_MAX_CHARS of the transport, decoded), and the read-back's poll
# (the maintainer's decision K17: up to 30 minutes, every 30 s, never past the token's
# bound less ReadMarginSeconds).
$script:ReplicaStage = '7'
$script:OdjFileDc1 = 'C:\NewtonBuild\out\s7-odj.txt'
$script:OdjFileDc2 = 'C:\NewtonBuild\s7-odj.txt'
$script:OdjMaxChars = 32768
$script:OdjMaxBytes = 24576
$script:OdjPattern = '\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\z'
$script:ReadMaxSeconds = 1800
$script:ReadPollSeconds = 30
$script:ReadMarginSeconds = 120
# DC2's own dcdiag wait: 15 minutes (the lab run of 2026-11-23 measured
# the first replication of a promoted DC2 settling in more than eight
# minutes; the runner waits this long too, run.S7_DC_DIAG_MAX_S).
$script:DiagMaxSeconds = 900
$script:DiagPollSeconds = 60
# The margin of one pass (a repadmin and a dcdiag) that the dcdiag wait
# leaves inside the token's bound: the wait is a hard limit, but a pass
# that starts before it may end after it (the runner waits this long too,
# run.S7_DC_PASS_MARGIN_S).
$script:DiagPassMarginSeconds = 180

# The info string of the DSRM secret (plan.DSRM_INFO).
$script:DsrmInfo = 'newton-ad-build-dsrm-v1'
# The salt of the derived secrets of the request (Get-NewtonSecretsDigest),
# set when its plan bytes are read.
$script:SecretsDigest = ''

# The info string of the owner's first admin password (plan.ADMIN_INFO):
# stage 5 creates the owner's admin account with it.
$script:AdminInfo = 'newton-ad-build-admin-v1'

# The baselines this helper holds compiled in (DESIGN-1.5 "Baseline";
# baseline-<version>.toml, which test_build_baseline.py holds equal to
# this table).  A plan of another version renders nothing.  Each GPO
# setting is 'key|value name|DWORD'.
$script:Baselines = @{
    '2026.11' = [ordered]@{
        PasswordMinLength = '14'
        PasswordHistory = '24'
        PasswordMaxAgeDays = '365'
        PasswordMinAgeDays = '1'
        PasswordComplexity = 'True'
        PasswordReversible = 'False'
        LockoutThreshold = '10'
        LockoutMinutes = '15'
        LockoutWindowMinutes = '15'
        PsoName = 'Newton Tier 0 Admins'
        PsoPrecedence = '10'
        PsoMinLength = '20'
        ProtectedUsers = 'True'
        DomainGpoName = 'Newton Baseline 2026.11 Domain'
        DomainGpoLink = 'domain'
        DomainGpoSettings = [string[]]@(
            'HKLM\System\CurrentControlSet\Control\Lsa|LmCompatibilityLevel|5',
            'HKLM\System\CurrentControlSet\Control\Lsa|NoLMHash|1',
            'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinClientSec|537395200',
            'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinServerSec|537395200',
            'HKLM\System\CurrentControlSet\Control\Lsa|RestrictAnonymousSAM|1',
            'HKLM\System\CurrentControlSet\Control\Lsa|RestrictAnonymous|1',
            'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters|RequireSecuritySignature|1')
        DcGpoName = 'Newton Baseline 2026.11 Domain Controllers'
        DcGpoLink = 'dc'
        DcGpoSettings = [string[]]@(
            'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature|1',
            'HKLM\System\CurrentControlSet\Services\NTDS\Parameters|LDAPServerIntegrity|2',
            'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS|BackupDirectory|2',
            'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS|ADPasswordEncryptionEnabled|1',
            'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS|ADBackupDSRMPassword|1')
        # The values of the security template: the ones the export of the
        # security policy (the area secedit exports) holds.  The Windows
        # LAPS policy is not one of them, so the export never holds it and
        # the read of the registry proves it.
        SecurityGpoSettings = [string[]]@(
            'HKLM\System\CurrentControlSet\Control\Lsa|LmCompatibilityLevel|5',
            'HKLM\System\CurrentControlSet\Control\Lsa|NoLMHash|1',
            'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinClientSec|537395200',
            'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinServerSec|537395200',
            'HKLM\System\CurrentControlSet\Control\Lsa|RestrictAnonymousSAM|1',
            'HKLM\System\CurrentControlSet\Control\Lsa|RestrictAnonymous|1',
            'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters|RequireSecuritySignature|1',
            'HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters|RequireSecuritySignature|1',
            'HKLM\System\CurrentControlSet\Services\NTDS\Parameters|LDAPServerIntegrity|2')
    }
}

# The options of the built-in Administrator (plan.BASELINE_OPTIONS).
$script:AdministratorOptions = @('random-password', 'disabled')

# The grammars of the names of stage 5 (plan.NAME_RE, OWNER_ADMIN_RE and
# RESERVED_OWNER_ADMINS).
$script:NamePattern = '\A[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}\z'
$script:OwnerAdminPattern = '\A[A-Za-z0-9][A-Za-z0-9_.-]{7,19}\z'
$script:ReservedOwnerAdmins = @('newton-build', 'administrator', 'guest', 'krbtgt', 'defaultaccount', 'wdagutilityaccount')

# The secret alphabets and length of plan._encode_secret.
$script:SecretLength = 24
$script:SecretUpper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
$script:SecretLower = 'abcdefghijkmnopqrstuvwxyz'
$script:SecretDigit = '23456789'
$script:SecretSymbol = '!@#$%^&*-+=_'

# Stage 0 (DESIGN-1.5, the stage table): the clock within 5 minutes of
# the NBF of the request, 20 GB free.
$script:ClockSkewSeconds = 300
$script:MinFreeBytes = [int64]20 * 1024 * 1024 * 1024

# The longest the helper waits: for Get-ADDomain after a boot
# (MEASURED-1.5: 333 s after the first boot) and for a password task.
# The task wait is 10 minutes: the longest measured op, the promotion,
# took 139 s in its task (144 s from the helper's call), every other op
# 5 to 12 s (MEASURED-1.5, the ops of stages 0 to 4), so 600 s holds the
# promotion four times over and ends well inside the 30-minute token of
# an irreversible stage (PLAN-1.5 Constraints).  A run also never waits
# past the EXP of its token less TaskAnswerMarginSeconds, so its answer,
# 'running' included, comes back while the token is open; an op that
# outlives the wait is recorded by a status request from its result file
# (Invoke-NewtonTemplateRecord), until EXP plus PostBootGraceSeconds and,
# from its result file, after it.  The task's own limit is 60 minutes.
$script:DirectoryWaitSeconds = 900
$script:TaskWaitSeconds = 600
$script:TaskAnswerMarginSeconds = 30

# The least time a stage 2 run needs before its token's answer margin:
# the longest measured promotion took 144 s from the helper's call (139
# s and 142 s in the other runs), and s2-role runs before it (9 s in a
# task); 180 s holds both with room (MEASURED-1.5, the ops of stages 0
# to 4 and "Stage 2 resumed").  A stage 2 run with less than this plus
# TaskAnswerMarginSeconds left on its token is refused window_short
# before anything starts (every stage 2 run, a resumed one that will not
# promote included), so a promotion starts with its measured time left
# for the run's first answer, and the run never starts one with no wait
# at all.  The check is made once: a role read slower than the room in
# the minimum shortens the wait, and a promotion that outlives it is
# answered 'running' and recorded by the status record path.
$script:PromotionMinimumSeconds = 180

# A task that has not left LastTaskResult 267011 (SCHED_S_TASK_HAS_NOT_RUN)
# this long after Start-ScheduledTask did not start: the helper gives up
# on it rather than wait the whole TaskWaitSeconds.  Before it gives up
# it disables the task (a disabled task does not start) and reads it
# again, so a task that started in that moment is waited for, not
# reported as one that never ran.
$script:TaskNotRunResult = 267011
# A task that is running reads LastTaskResult 267009 (SCHED_S_TASK_RUNNING),
# and for a moment after it ended too; the read settles within this.
$script:TaskRunningResult = 267009
$script:TaskResultSettleSeconds = 30
$script:TaskStartSeconds = 120

# Stage 2: after the reboot that refreshes the groups, at most this many
# more reboots wait for msDS-GenerationId (measured: none was needed).
$script:GenerationIdReboots = 2

# The dcdiag tests a fresh forest must pass, and the two it is allowed
# to fail on events of its own first boots (MEASURED-1.5, stage 2).
$script:DcdiagMustPass = @(
    'Connectivity', 'Advertising', 'FrsEvent', 'SysVolCheck', 'KccEvent',
    'KnowsOfRoleHolders', 'MachineAccount', 'NCSecDesc', 'NetLogons',
    'ObjectsReplicated', 'Replications', 'RidManager', 'Services',
    'VerifyReferences', 'CheckSDRefDom', 'CrossRefValidation',
    'LocatorCheck', 'Intersite')
$script:DcdiagAcceptedFailures = @('DFSREvent', 'SystemLog')
# The tests of the list dcdiag runs on the partitions and the enterprise,
# not on the server: their lines name a partition or the domain, so any
# subject passes them.  Every other test of the list must name the server
# dcdiag ran against (stage 7's read-back, X3 of a review).
$script:DcdiagEnterpriseTests = @('CheckSDRefDom', 'CrossRefValidation', 'LocatorCheck', 'Intersite')

# The functional levels of the plan grammar and how the directory names
# them (MEASURED-1.5, stage 2).
$script:LevelNames = @{
    'Win2025' = @{ forest = 'Windows2025Forest'; domain = 'Windows2025Domain'; version = '10' }
}

# The domain functional levels of Windows Server and their
# msDS-Behavior-Version numbers (plan.DOMAIN_LEVELS, the numbers the
# directory holds).  The design builds the forest at 2025 only; this
# table is here for the one refusal that names a level: the Windows
# LAPS policy of the baseline (ADPasswordEncryptionEnabled) needs the
# domain functional level 2016 or later, so a plan that asks for an
# older level is refused, and the refusal says why.
$script:DomainLevels = @{
    'Win2000' = 0
    'WinXP' = 1
    'Win2003' = 2
    'Win2008' = 3
    'Win2008R2' = 4
    'Win2012' = 5
    'Win2012R2' = 6
    'Win2016' = 7
    'Win2019' = 8
    'Win2022' = 9
    'Win2025' = 10
}

# The domain functional level the Windows LAPS policy of the baseline
# needs (plan.LAPS_MINIMUM_DOMAIN_LEVEL).
$script:LapsMinimumDomainLevel = 7

# The SIDs of the three groups of stage 2, by their RID.
$script:BuildGroupRids = @('512', '518', '519')

# The LAPS schema of stage 4 (MEASURED-1.5, stage 4): the attributes and
# their schemaIDGUIDs, the mayContain of the computer class, and the
# three explicit SELF ACEs of the self-permission.
# The LAPS attributes and their lDAPDisplayNames.  Their schemaIDGUIDs
# are not constants: Update-LapsADSchema leaves them to the directory,
# and the two measured forests have different ones (MEASURED-1.5, "Stage
# 4 on the Domain Controllers OU").  The read-back takes each GUID from
# the op's own schema read and holds the ACEs to it.
$script:LapsAttributes = [ordered]@{
    'ms-LAPS-Password' = 'msLAPS-Password'
    'ms-LAPS-PasswordExpirationTime' = 'msLAPS-PasswordExpirationTime'
    'ms-LAPS-EncryptedPassword' = 'msLAPS-EncryptedPassword'
    'ms-LAPS-EncryptedPasswordHistory' = 'msLAPS-EncryptedPasswordHistory'
    'ms-LAPS-EncryptedDSRMPassword' = 'msLAPS-EncryptedDSRMPassword'
    'ms-LAPS-EncryptedDSRMPasswordHistory' = 'msLAPS-EncryptedDSRMPasswordHistory'
}
$script:GuidPattern = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
$script:LapsMayContain = 'msLAPS-CurrentPasswordVersion, msLAPS-EncryptedDSRMPassword, msLAPS-EncryptedDSRMPasswordHistory, msLAPS-EncryptedPassword, msLAPS-EncryptedPasswordHistory, msLAPS-Password, msLAPS-PasswordExpirationTime'
$script:ComputerClassGuid = 'bf967a86-0de6-11d0-a285-00aa003049e2'
# The three explicit SELF ACEs: two name an attribute (its GUID is the
# forest's own), one the extended right ms-LAPS-Encrypted-Password-
# Attributes, whose rightsGuid is the same in both measured forests.
$script:LapsSelfAces = @(
    @{ rights = 'ReadProperty, WriteProperty'; attribute = 'msLAPS-PasswordExpirationTime' },
    @{ rights = 'ReadProperty, WriteProperty, ExtendedRight'; object = 'f3531ec6-6330-4f8e-8d39-7a671fbac605' },
    @{ rights = 'WriteProperty'; attribute = 'msLAPS-Password' }
)

# The grammars of the values (plan.py: DNS_NAME_RE, NETBIOS_RE,
# HOSTNAME_RE, an IPv4 address, a prefix of 1 to 30; the address checks
# beyond the grammar are Assert-NewtonPlanAddresses).  plan.py also
# refuses a hostname or a NetBIOS name that is all digits and a DNS
# name whose last label is all digits: DigitsPattern is that check.
$script:DnsNamePattern = '\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\z'
$script:NetbiosPattern = '\A[A-Za-z0-9][A-Za-z0-9-]{0,14}\z'
$script:HostNamePattern = '\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?\z'
$script:Ipv4Pattern = '\A(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\z'
$script:PrefixPattern = '\A(?:[1-9]|[12][0-9]|30)\z'
$script:DigitsPattern = '\A[0-9]+\z'
$script:CheckpointPattern = '\A(hyperv|proxmox|wbadmin)\z'

function Get-NewtonPlanServerIndex {
    # The index of the server of one role in the plan.
    param([hashtable]$Plan, [string]$Role)
    $index = 0
    while ($Plan.ContainsKey('servers.' + [string]$index + '.role')) {
        if ([string]$Plan['servers.' + [string]$index + '.role'] -ceq $Role) { return $index }
        $index = $index + 1
    }
    Throw-NewtonRefusal 'schema' 'the plan holds no server of that role'
}

function Get-NewtonPlanValue {
    # One value of the plan, checked against its grammar.
    param([hashtable]$Plan, [string]$Key, [string]$Pattern)
    if (-not $Plan.ContainsKey($Key)) {
        Throw-NewtonRefusal 'schema' ('the plan holds no ' + $Key)
    }
    $value = [string]$Plan[$Key]
    if ($value -cnotmatch $Pattern) {
        Throw-NewtonRefusal 'schema' ('the plan value ' + $Key + ' is outside its grammar')
    }
    return $value
}

function ConvertTo-NewtonIpv4Number {
    # A dotted quad that matched Ipv4Pattern, as its 32-bit number.
    param([string]$Address)
    $number = [int64]0
    foreach ($part in $Address.Split('.')) { $number = ($number * 256) + [int64]$part }
    return $number
}

function Test-NewtonUsableIpv4 {
    # plan.py: an address is not unspecified (0.0.0.0), loopback
    # (127/8), multicast (224/4), link-local (169.254/16) or reserved
    # (240/4, Python's is_reserved, which holds 255.255.255.255).
    param([int64]$Number)
    if ($Number -eq 0) { return $false }
    $first = [Math]::Floor($Number / 16777216)
    if ($first -eq 127) { return $false }
    if ($first -ge 224) { return $false }
    if ([Math]::Floor($Number / 65536) -eq ((169 * 256) + 254)) { return $false }
    return $true
}

function Assert-NewtonPlanAddresses {
    # The address checks of plan.py on the values of one server: the
    # address and the gateway usable, neither the network nor the
    # broadcast address of address/prefix, the gateway not the address
    # and inside the network; each forwarder usable, not the address,
    # and none twice.
    param([string]$Ip, [string]$Prefix, [string]$Gateway, [string[]]$Forwarders)
    $ipNumber = ConvertTo-NewtonIpv4Number $Ip
    $gatewayNumber = ConvertTo-NewtonIpv4Number $Gateway
    $hostBits = [int64][Math]::Pow(2, 32 - [int]$Prefix)
    $network = [Math]::Floor($ipNumber / $hostBits) * $hostBits
    $broadcast = $network + $hostBits - 1
    if (-not (Test-NewtonUsableIpv4 $ipNumber)) {
        Throw-NewtonRefusal 'schema' 'the plan value of the IP address is an address that cannot be used'
    }
    if (-not (Test-NewtonUsableIpv4 $gatewayNumber)) {
        Throw-NewtonRefusal 'schema' 'the plan value of the gateway is an address that cannot be used'
    }
    if (($ipNumber -eq $network) -or ($ipNumber -eq $broadcast)) {
        Throw-NewtonRefusal 'schema' 'the plan value of the IP address is an address of the network'
    }
    if (($gatewayNumber -eq $network) -or ($gatewayNumber -eq $broadcast)) {
        Throw-NewtonRefusal 'schema' 'the plan value of the gateway is an address of the network'
    }
    if ($gatewayNumber -eq $ipNumber) {
        Throw-NewtonRefusal 'schema' 'the plan value of the gateway is the address of the server'
    }
    if (($gatewayNumber -lt $network) -or ($gatewayNumber -gt $broadcast)) {
        Throw-NewtonRefusal 'schema' 'the plan value of the gateway is outside the network of the server'
    }
    $seen = @{}
    foreach ($forwarder in $Forwarders) {
        $number = ConvertTo-NewtonIpv4Number $forwarder
        if ($seen.ContainsKey($number)) {
            Throw-NewtonRefusal 'schema' 'the plan holds a DNS forwarder twice'
        }
        $seen[$number] = $true
        if ((-not (Test-NewtonUsableIpv4 $number)) -or ($number -eq $ipNumber)) {
            Throw-NewtonRefusal 'schema' 'a DNS forwarder of the plan cannot be used'
        }
    }
}

function Get-NewtonStageValues {
    # The values the ops of one server are rendered with, out of the
    # plan bytes.  The helper checks each one against its grammar even
    # though the bytes are signed: a value outside its grammar is never
    # rendered.
    param([hashtable]$Plan, [string]$Role)
    $index = Get-NewtonPlanServerIndex -Plan $Plan -Role $Role
    $prefix = 'servers.' + [string]$index + '.'
    $dns = Get-NewtonPlanValue -Plan $Plan -Key 'domain.dns_name' -Pattern $script:DnsNamePattern
    if (($dns.Length -gt 253) -or ($dns.Split('.')[-1] -cmatch $script:DigitsPattern)) {
        Throw-NewtonRefusal 'schema' 'the plan value domain.dns_name is outside its grammar'
    }
    $netbios = Get-NewtonPlanValue -Plan $Plan -Key 'domain.netbios' -Pattern $script:NetbiosPattern
    $hostName = Get-NewtonPlanValue -Plan $Plan -Key ($prefix + 'hostname') -Pattern $script:HostNamePattern
    foreach ($name in @('domain.netbios', ($prefix + 'hostname'))) {
        if ([string]$Plan[$name] -cmatch $script:DigitsPattern) {
            Throw-NewtonRefusal 'schema' ('the plan value ' + $name + ' is outside its grammar')
        }
    }
    $level = [string]$Plan['domain.functional_level']
    # The level of the plan: the design builds the forest at 2025 only,
    # and the Windows LAPS policy of the baseline needs 2016 or later.
    Assert-NewtonPlanDomainLevel -Plan $Plan
    $gateway = Get-NewtonPlanValue -Plan $Plan -Key ($prefix + 'gateway') -Pattern $script:Ipv4Pattern
    if (-not $Plan.ContainsKey($prefix + 'forwarders')) {
        Throw-NewtonRefusal 'schema' 'the plan holds no forwarders for this server'
    }
    $forwarders = New-Object System.Collections.ArrayList
    foreach ($one in ([string]$Plan[$prefix + 'forwarders']).Split(',')) {
        if ($one -cnotmatch $script:Ipv4Pattern) {
            Throw-NewtonRefusal 'schema' 'a forwarder of the plan is outside its grammar'
        }
        [void]$forwarders.Add($one)
    }
    $ip = Get-NewtonPlanValue -Plan $Plan -Key ($prefix + 'ip') -Pattern $script:Ipv4Pattern
    $ipPrefix = Get-NewtonPlanValue -Plan $Plan -Key ($prefix + 'prefix') -Pattern $script:PrefixPattern
    Assert-NewtonPlanAddresses -Ip $ip -Prefix $ipPrefix -Gateway $gateway -Forwarders ([string[]]$forwarders.ToArray())
    $values = [ordered]@{
        DnsName = $dns
        Netbios = $netbios
        Level = $level
        HostName = $hostName
        Ip = $ip
        Prefix = $ipPrefix
        Gateway = $gateway
        TimePeer = $gateway
        Forwarders = [string[]]$forwarders.ToArray()
        Checkpoint = (Get-NewtonPlanValue -Plan $Plan -Key ($prefix + 'checkpoint') -Pattern $script:CheckpointPattern)
        BuildUser = $script:BuildUser
        SecretFile = $script:BuildDir + '\dsrm.bin'
    }
    foreach ($pair in (Get-NewtonStructureValues -Plan $Plan).GetEnumerator()) { $values[$pair.Key] = $pair.Value }
    return $values
}

function Get-NewtonPlanList {
    # A list value of the plan: comma-separated, possibly empty.
    param([hashtable]$Plan, [string]$Key)
    if (-not $Plan.ContainsKey($Key)) { Throw-NewtonRefusal 'schema' ('the plan holds no ' + $Key) }
    $text = [string]$Plan[$Key]
    if ($text -eq '') { return ,([string[]]@()) }
    return ,([string[]]$text.Split(','))
}

function Get-NewtonStructureValues {
    # The values of stages 5 and 6: the OU tree, the groups and the
    # owner's admin account of the plan, each checked against the plan
    # grammar, the option of the built-in Administrator, and the baseline
    # of the plan's version, compiled into this helper.
    param([hashtable]$Plan)
    $ouTree = New-Object System.Collections.ArrayList
    foreach ($path in (Get-NewtonPlanList -Plan $Plan -Key 'domain.ou_tree')) {
        foreach ($name in $path.Split('/')) {
            if ($name -cnotmatch $script:NamePattern) {
                Throw-NewtonRefusal 'schema' 'a name of the OU tree of the plan is outside its grammar'
            }
        }
        [void]$ouTree.Add($path)
    }
    $groups = New-Object System.Collections.ArrayList
    foreach ($group in (Get-NewtonPlanList -Plan $Plan -Key 'domain.groups')) {
        if ($group -cnotmatch $script:NamePattern) {
            Throw-NewtonRefusal 'schema' 'a group of the plan is outside its grammar'
        }
        [void]$groups.Add($group)
    }
    $owner = Get-NewtonPlanValue -Plan $Plan -Key 'domain.owner_admin' -Pattern $script:OwnerAdminPattern
    if ($script:ReservedOwnerAdmins -contains $owner.ToLowerInvariant()) {
        Throw-NewtonRefusal 'schema' 'the owner admin of the plan is a reserved name'
    }
    $version = [string]$Plan['baseline.version']
    if (-not $script:Baselines.ContainsKey($version)) {
        Throw-NewtonRefusal 'schema' 'the helper holds no baseline of the version of the plan'
    }
    $option = ''
    foreach ($pair in ([string]$Plan['baseline.options']).Split(',')) {
        $key, $value = $pair.Split('=', 2)
        if ($key -cne 'administrator') {
            Throw-NewtonRefusal 'schema' 'the plan holds a baseline option this helper does not know'
        }
        $option = [string]$value
    }
    if ($script:AdministratorOptions -cnotcontains $option) {
        Throw-NewtonRefusal 'schema' 'the option of the built-in Administrator is not one of the baseline'
    }
    $values = [ordered]@{
        OuTree = [string[]]$ouTree.ToArray()
        Groups = [string[]]$groups.ToArray()
        OwnerAdmin = $owner
        AdministratorOption = $option
        AdminSecretFile = $script:BuildDir + '\admin.bin'
        BaselineVersion = $version
    }
    $baseline = $script:Baselines[$version]
    foreach ($key in $baseline.Keys) { $values[$key] = $baseline[$key] }
    $values['GpoNames'] = [string[]]@($baseline['DomainGpoName'], $baseline['DcGpoName'])
    $values['GpoSettings'] = [string[]](@($baseline['DomainGpoSettings']) + @($baseline['DcGpoSettings']))
    return $values
}

# ---------------------------------------------------------------------------
# the renderer
# ---------------------------------------------------------------------------

function ConvertTo-NewtonLiteral {
    # A PowerShell single-quoted string that holds a value.  Each of the
    # four single quotes PowerShell ends a single-quoted string at (the
    # ASCII one and U+2018, U+2019, U+201A, U+201B) is doubled; nothing
    # else is touched, as bootstrap._escape does.
    param([string]$Value)
    if ($null -eq $Value) { $Value = '' }
    if ($Value.Contains([string][char]0)) {
        Throw-NewtonRefusal 'schema' 'a value of an op holds a NUL'
    }
    $quotes = "['" + [string][char]0x2018 + [string][char]0x2019 + [string][char]0x201A + [string][char]0x201B + "]"
    return "'" + [regex]::Replace($Value, $quotes, { param($m) $m.Value + $m.Value }) + "'"
}

function ConvertTo-NewtonListLiteral {
    # An array of single-quoted strings.
    param([string[]]$Values)
    $parts = New-Object System.Collections.ArrayList
    foreach ($one in $Values) { [void]$parts.Add((ConvertTo-NewtonLiteral $one)) }
    return '@(' + ($parts.ToArray() -join ', ') + ')'
}

# The stage of each op and the values each op is rendered with.
$script:OpStage = [ordered]@{
    's0-read' = '0'
    's1-base' = '1'
    's1-read' = '1'
    's2-role' = '2'
    's2-promote' = '2'
    's2-groups' = '2'
    's2-genid' = '2'
    's2-read' = '2'
    's3-recyclebin' = '3'
    's3-state' = '3'
    's4-laps' = '4'
    's4-groups' = '4'
    's4-state' = '4'
    's5-structure' = '5'
    's6-gpo-domain' = '6'
    's6-gpo-dc' = '6'
    's6-read' = '6'
    's7-provision' = '7'
    's7-install' = '7'
    's7-read' = '7'
    's7-join' = '7'
    's7-member' = '7'
    's7-dc' = '7'
    's8-audit' = '8'
    's8-ops' = '8'
    's8-restart' = '8'
    's8-read' = '8'
    's9-da' = '9'
    's9-register' = '9'
}
$script:OpValues = @{
    's0-read' = @('DnsName', 'Ip')
    's1-base' = @('HostName', 'Ip', 'TimePeer', 'Forwarders')
    's1-read' = @('Ip')
    's2-role' = @()
    's2-promote' = @('DnsName', 'Netbios', 'Level', 'SecretFile')
    's2-groups' = @('BuildUser')
    's2-genid' = @()
    's2-read' = @('DnsName', 'BuildUser')
    's3-recyclebin' = @('DnsName')
    's3-state' = @()
    's4-laps' = @('BuildUser')
    's4-groups' = @('BuildUser')
    's4-state' = @('BuildUser')
    's5-structure' = @('OuTree', 'Groups', 'OwnerAdmin', 'AdministratorOption', 'AdminSecretFile',
        'PasswordMinLength', 'PasswordHistory', 'PasswordMaxAgeDays',
        'PasswordMinAgeDays', 'LockoutThreshold', 'LockoutMinutes', 'LockoutWindowMinutes',
        'PsoName', 'PsoPrecedence', 'PsoMinLength')
    's6-gpo-domain' = @('BaselineVersion', 'GpoName=DomainGpoName', 'GpoLink=DomainGpoLink', 'Settings=DomainGpoSettings')
    's6-gpo-dc' = @('BaselineVersion', 'GpoName=DcGpoName', 'GpoLink=DcGpoLink', 'Settings=DcGpoSettings')
    's6-read' = @('GpoNames', 'Settings=GpoSettings')
    's7-provision' = @('DnsName', 'Dc2Host', 'BlobFile', 'Reuse')
    's7-install' = @('DnsName', 'Netbios', 'BuildUser', 'Dc2Host', 'Dc2Fqdn', 'SiteName')
    's7-read' = @('Dc1Host', 'Dc2Host', 'ReadWaitSeconds', 'ReadPollSeconds')
    's7-join' = @('DnsName', 'Ip', 'Dc1Ip', 'BlobFile')
    's7-member' = @()
    's7-dc' = @('DnsName', 'Dc1Host', 'Dc2Host', 'DiagWaitSeconds', 'DiagPollSeconds')
    's8-audit' = @('SetupScript')
    's8-ops' = @('SetupScript')
    's8-restart' = @('RestartB64', 'RestartScript', 'RestartTask')
    's8-read' = @('Netbios', 'AdDir', 'BuildKey')
    's9-da' = @('BuildUser')
    's9-register' = @('CleanupB64', 'CleanupScript', 'CleanupTask')
}

# The values that are lists: an array of single-quoted strings.
$script:ListValues = @('Forwarders', 'OuTree', 'Groups', 'DomainGpoSettings', 'DcGpoSettings', 'GpoSettings', 'GpoNames', 'SecurityGpoSettings')

# The body of each op, where it is not the op's own name: the two GPO
# ops of stage 6 run one body, each with the values of its GPO.
$script:OpBodyOf = @{ 's6-gpo-domain' = 's6-gpo'; 's6-gpo-dc' = 's6-gpo'; 's8-audit' = 's8-setup'; 's8-ops' = 's8-setup' }

# The bodies of the ops.  They are constant text: the values are the
# variables the header of the op assigns.
$script:OpBodies = @{}

$script:OpBodies['s0-read'] = @'
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
'@

$script:OpBodies['s1-base'] = @'
function Get-NewtonIpLine {
    $address = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Ip
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $address.InterfaceIndex
    'ip: ' + $address.IPAddress + '/' + $address.PrefixLength + ' ' + $address.PrefixOrigin + ' gw ' + (@($route | ForEach-Object { $_.NextHop }) -join ',')
}
'before ' + (Get-NewtonIpLine)
$sw = [Diagnostics.Stopwatch]::StartNew()
if ($env:COMPUTERNAME -ne $HostName) {
    Rename-Computer -NewName $HostName -Force -WarningAction Continue 3>&1 | ForEach-Object { 'Rename-Computer: ' + $_ }
}
'Rename-Computer done in ' + $sw.ElapsedMilliseconds + ' ms'
$sw.Restart()
w32tm /config ('/manualpeerlist:' + $TimePeer + ',0x8') /syncfromflags:manual /reliable:yes /update
'w32tm /config exit ' + $LASTEXITCODE
Restart-Service -Name w32time
w32tm /query /configuration | Select-String -Pattern 'NtpServer|Type:|AnnounceFlags'
'w32tm done in ' + $sw.ElapsedMilliseconds + ' ms'
$index = (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Ip).InterfaceIndex
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $Forwarders
'dns client: ' + ((Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $index).ServerAddresses -join ',')
$sw.Restart()
$r = Install-WindowsFeature AD-Domain-Services, RSAT-AD-Tools, Windows-Server-Backup
'Install-WindowsFeature in ' + $sw.ElapsedMilliseconds + ' ms: Success ' + $r.Success + ' RestartNeeded ' + $r.RestartNeeded + ' ExitCode ' + $r.ExitCode
$r.FeatureResult | Format-Table -AutoSize Name, Success, RestartNeeded | Out-String -Width 200
'after ' + (Get-NewtonIpLine)
'@

$script:OpBodies['s1-read'] = @'
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
'@

# The role of the server before stage 2 promotes it (MEASURED-1.5, "Stage
# 2 resumed: the role of the server"): a resumed stage 2 whose promotion
# already succeeded must not run Install-ADDSForest again.
$script:OpBodies['s2-role'] = @'
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
'cs: Name ' + $cs.Name + ' | DomainRole ' + $cs.DomainRole + ' | PartOfDomain ' + $cs.PartOfDomain + ' | Domain ' + $cs.Domain + ' | Workgroup ' + $cs.Workgroup
'ProductType: ' + (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
$ntds = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
if ($ntds) { 'NTDS Parameters: present | Root Domain ' + $ntds.'Root Domain' + ' | Machine DN Name ' + $ntds.'Machine DN Name' } else { 'NTDS Parameters: absent' }
$svc = Get-Service -Name NTDS -ErrorAction SilentlyContinue
'NTDS service: ' + $(if ($svc) { [string]$svc.Status + ', ' + [string]$svc.StartType } else { 'absent' })
try { $d = Get-ADDomain -ErrorAction Stop; 'Get-ADDomain: DNSRoot ' + $d.DNSRoot + ' | NetBIOSName ' + $d.NetBIOSName } catch { 'Get-ADDomain: FAIL ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message }
'@

$script:OpBodies['s2-promote'] = @'
Add-Type -AssemblyName System.Security
$sec = ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($SecretFile), $null, 'LocalMachine'))) -AsPlainText -Force
Remove-Item -LiteralPath $SecretFile; 'dsrm.bin deleted: ' + (-not (Test-Path -LiteralPath $SecretFile))
$sw = [Diagnostics.Stopwatch]::StartNew()
$r = Install-ADDSForest -DomainName $DnsName -DomainNetbiosName $Netbios -ForestMode $Level -DomainMode $Level -InstallDns -SafeModeAdministratorPassword $sec -NoRebootOnCompletion -Force
'Install-ADDSForest returned after ' + [int]$sw.Elapsed.TotalSeconds + ' s'
$r | Format-List * | Out-String -Width 250
'@

$script:OpBodies['s2-groups'] = @'
'token groups at task start: ' + ((whoami /groups /fo csv /nh | Where-Object { $_ -match '-512"|-518"|-519"|S-1-5-32-544' } | ForEach-Object { ($_ -split '","')[2] }) -join ', ')
foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins') { Add-ADGroupMember -Identity $g -Members $BuildUser; 'Add-ADGroupMember ''' + $g + ''' ' + $BuildUser + ': ok' }
'Get-ADPrincipalGroupMembership: ' + ((Get-ADPrincipalGroupMembership -Identity $BuildUser | ForEach-Object Name | Sort-Object) -join ', ')
'@

$script:OpBodies['s2-genid'] = @'
$c = Get-ADComputer -Identity $env:COMPUTERNAME -Properties msDS-GenerationId, whenCreated
$g = $c.'msDS-GenerationId'
'msDS-GenerationId on ' + $c.DistinguishedName + ': ' + $(if ($g) { 'present, ' + $g.Length + ' bytes, ' + (($g | ForEach-Object { $_.ToString('x2') }) -join '') } else { 'absent' })
'uptime s ' + [int]((Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime).TotalSeconds
Get-WinEvent -LogName 'Directory Service' -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 2168, 2170, 2172, 2173, 2179, 1109 } | Sort-Object TimeCreated | ForEach-Object { '  DS event ' + $_.Id + ' at ' + $_.TimeCreated.ToUniversalTime().ToString('o') + ': ' + ($_.Message -split "`n")[0].Trim() }
'@

$script:OpBodies['s2-read'] = @'
$sw = [Diagnostics.Stopwatch]::StartNew()
$dd = dcdiag /q; 'dcdiag /q exit ' + $LASTEXITCODE + ' in ' + [int]$sw.Elapsed.TotalSeconds + ' s, ' + @($dd).Count + ' lines:'; $dd
$sw.Restart(); $d = dcdiag; 'dcdiag exit ' + $LASTEXITCODE + ' in ' + [int]$sw.Elapsed.TotalSeconds + ' s; test lines:'; $d | Select-String -Pattern 'passed test|failed test'
Get-SmbShare | Where-Object Name -in 'SYSVOL', 'NETLOGON' | Format-Table -AutoSize Name, Path | Out-String
'SYSVOLReady: ' + (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').SysvolReady
foreach ($n in @('_ldap._tcp.dc._msdcs.', '_kerberos._tcp.', '_gc._tcp.', '_ldap._tcp.pdc._msdcs.')) {
    $name = $n + $DnsName
    try { Resolve-DnsName -Name $name -Type SRV -DnsOnly -ErrorAction Stop | Where-Object Type -eq 'SRV' | ForEach-Object { 'SRV ' + $_.Name + ' -> ' + $_.NameTarget + ':' + $_.Port } } catch { 'SRV ' + $name + ' FAIL: ' + $_.Exception.Message }
}
$f = Get-ADForest; $dm = Get-ADDomain
'ForestMode ' + $f.ForestMode + ' DomainMode ' + $dm.DomainMode + ' | forest ' + $f.Name + ' | NetBIOS ' + $dm.NetBIOSName + ' | DomainSID ' + $dm.DomainSID
'msDS-Behavior-Version: forest ' + (Get-ADObject ('CN=Partitions,' + (Get-ADRootDSE).configurationNamingContext) -Properties msDS-Behavior-Version).'msDS-Behavior-Version' + ' domain ' + (Get-ADObject $dm.DistinguishedName -Properties msDS-Behavior-Version).'msDS-Behavior-Version'
'dns client after promotion: ' + ((Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses }) -join ',')
'DNS forwarders: ' + ((Get-DnsServerForwarder).IPAddress.IPAddressToString -join ',')
$BuildUser + ' memberships (Get-ADPrincipalGroupMembership): ' + ((Get-ADPrincipalGroupMembership -Identity $BuildUser | ForEach-Object Name | Sort-Object) -join ', ')
'@

$script:OpBodies['s3-recyclebin'] = @'
'token groups: ' + ((whoami /groups /fo csv /nh | Where-Object { $_ -match '-512"|-518"|-519"' } | ForEach-Object { ($_ -split '","')[0].Trim('"') }) -join ', ')
$f = Get-ADOptionalFeature -Identity 'Recycle Bin Feature'
'before: EnabledScopes count ' + @($f.EnabledScopes).Count + ' | FeatureScope ' + ($f.FeatureScope -join ',') + ' | RequiredForestMode ' + $f.RequiredForestMode
$sw = [Diagnostics.Stopwatch]::StartNew()
Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $DnsName -Confirm:$false
'Enable-ADOptionalFeature returned in ' + $sw.ElapsedMilliseconds + ' ms'
$f = Get-ADOptionalFeature -Identity 'Recycle Bin Feature'
'after: EnabledScopes:'; $f.EnabledScopes | ForEach-Object { '  ' + $_ }
'msDS-EnabledFeature on Partitions: ' + ((Get-ADObject ('CN=Partitions,' + (Get-ADRootDSE).configurationNamingContext) -Properties msDS-EnabledFeature).'msDS-EnabledFeature' -join ' | ')
'@

# Stage 3 resumed (bug hunt R1): the state s3-recyclebin
# leaves, read and never written.  It prints the feature's scopes and the
# msDS-EnabledFeature of the Partitions container in the lines
# s3-recyclebin prints them, with 'now' for 'before' and 'after', so a
# resumed stage 3 tells the state before Enable-ADOptionalFeature from
# the state after it.
$script:OpBodies['s3-state'] = @'
$f = Get-ADOptionalFeature -Identity 'Recycle Bin Feature'
'now: EnabledScopes count ' + @($f.EnabledScopes).Count + ' | FeatureScope ' + ($f.FeatureScope -join ',') + ' | RequiredForestMode ' + $f.RequiredForestMode
'now: EnabledScopes:'; $f.EnabledScopes | ForEach-Object { '  ' + $_ }
'msDS-EnabledFeature on Partitions: ' + ((Get-ADObject ('CN=Partitions,' + (Get-ADRootDSE).configurationNamingContext) -Properties msDS-EnabledFeature).'msDS-EnabledFeature' -join ' | ')
'@

$script:OpBodies['s4-laps'] = @'
$sc = (Get-ADRootDSE).schemaNamingContext
$names = 'ms-LAPS-Password', 'ms-LAPS-PasswordExpirationTime', 'ms-LAPS-EncryptedPassword', 'ms-LAPS-EncryptedPasswordHistory', 'ms-LAPS-EncryptedDSRMPassword', 'ms-LAPS-EncryptedDSRMPasswordHistory', 'ms-Mcs-AdmPwd'
function Get-NewtonSchemaRead {
    param([string]$When)
    'schema ' + $When + ' : objectVersion ' + (Get-ADObject $sc -Properties objectVersion).objectVersion
    foreach ($n in $names) { $o = Get-ADObject -SearchBase $sc -LDAPFilter ('(cn=' + $n + ')') -Properties lDAPDisplayName, schemaIDGUID; if ($o) { '  ' + $n + ' : present, lDAPDisplayName ' + $o.lDAPDisplayName + ', schemaIDGUID ' + [guid]$o.schemaIDGUID } else { '  ' + $n + ' : absent' } }
    $cc = Get-ADObject ('CN=Computer,' + $sc) -Properties mayContain
    '  computer mayContain msLAPS-*: ' + ((@($cc.mayContain) | Where-Object { $_ -like 'msLAPS-*' } | Sort-Object) -join ', ')
}
Get-NewtonSchemaRead 'before'
$sw = [Diagnostics.Stopwatch]::StartNew()
Update-LapsADSchema -Confirm:$false -Verbose 4>&1 | ForEach-Object { '  ' + $_ }
'Update-LapsADSchema returned in ' + $sw.ElapsedMilliseconds + ' ms'
Get-NewtonSchemaRead 'after'
$ou = 'OU=Domain Controllers,' + (Get-ADDomain).DistinguishedName
'Set-LapsADComputerSelfPermission: ' + $ou
Set-LapsADComputerSelfPermission -Identity $ou | Format-List * | Out-String -Width 250
$map = @{}; foreach ($n in $names) { $o = Get-ADObject -SearchBase $sc -LDAPFilter ('(cn=' + $n + ')') -Properties lDAPDisplayName, schemaIDGUID; if ($o) { $map[[string][guid]$o.schemaIDGUID] = $o.lDAPDisplayName } }
'OU ACEs for SELF:'
(Get-Acl -Path ('AD:' + $ou)).Access | Where-Object { $_.IdentityReference -like '*SELF' } | ForEach-Object { '  ' + $_.IdentityReference + ' | ' + $_.ActiveDirectoryRights + ' | ' + $_.AccessControlType + ' | ObjectType ' + $_.ObjectType + ' (' + $map[[string]$_.ObjectType] + ') | InheritanceType ' + $_.InheritanceType + ' | InheritedObjectType ' + $_.InheritedObjectType + ' | IsInherited ' + $_.IsInherited }
foreach ($g in 'Enterprise Admins', 'Schema Admins') { Remove-ADGroupMember -Identity $g -Members $BuildUser -Confirm:$false; 'Remove-ADGroupMember ''' + $g + ''' ' + $BuildUser + ': ok' }
'Get-ADPrincipalGroupMembership after: ' + ((Get-ADPrincipalGroupMembership -Identity $BuildUser | ForEach-Object Name | Sort-Object) -join ', ')
foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins') { '  ' + $g + ' members: ' + ((Get-ADGroupMember -Identity $g | ForEach-Object SamAccountName | Sort-Object) -join ', ') }
'@

# Stage 4 after its reboot (the maintainer's decision, 2026-11-13; MEASURED-1.5 "Stage
# 4 reboot, 2026-11-13/14"): the build account's groups in the directory,
# by the RIDs of Enterprise Admins (519) and Schema Admins (518).  It runs
# in the helper's own session, the S4U key login whose token the helper
# reads next to it.
$script:OpBodies['s4-groups'] = @'
$dom = Get-ADDomain
'LastBootUpTime: ' + (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
'domain: ' + $dom.DNSRoot + ' | DomainSID ' + $dom.DomainSID
'Get-ADPrincipalGroupMembership: ' + ((Get-ADPrincipalGroupMembership -Identity $BuildUser | Sort-Object -Property Name | ForEach-Object { $_.Name + ' (' + $_.SID + ')' }) -join ', ')
foreach ($rid in '519', '518') { $g = Get-ADGroup -Identity ([string]$dom.DomainSID + '-' + $rid); '  ' + $g.Name + ' (' + $g.SID + ') members: ' + ((Get-ADGroupMember -Identity $g -Recursive | ForEach-Object SamAccountName | Sort-Object) -join ', ') }
'@

# Stage 4 resumed (F1 of the stage 4 triage): the state s4-laps leaves,
# read and never written.  It prints the schema read of s4-laps (as
# 'schema now'), the SELF ACEs of the Domain Controllers OU and the build
# account's memberships, in the lines s4-laps prints them, so a resumed
# stage 4 tells the state before s4-laps from the state after it.
$script:OpBodies['s4-state'] = @'
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
'@

# Stage 5 (DESIGN-1.5, the stage table): the OU tree, the groups, the
# owner's admin account, Protected Users, the password policy, the
# fine-grained policy for admins and the built-in Administrator per the
# baseline option, then the read-back of every object and value.  The
# names are the plan's, assigned as single-quoted literals in the
# header; the body never builds a filter or a command out of them (an
# identity is a parameter, a DN is escaped).  The owner's admin secret
# comes through a DPAPI LocalMachine file the helper wrote, which the op
# reads and deletes first (DESIGN-1.5 "Secrets"); the built-in
# Administrator's random password is made in the op and never leaves it.  An object that is there
# already is left as it is (a resumed stage 5), and the read-back says
# what is there.
$script:OpBodies['s5-structure'] = @'
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
'@

# Stage 6 (DESIGN-1.5, the stage table): one op per baseline GPO.  The
# GPO is created, each registry value of the baseline is set in it with
# Set-GPRegistryValue (the supported cmdlet: it writes the GPO's
# Registry.pol and its versions), the GPO is linked, and the GPO is read
# back: its versions, its values and the links of its target.  A GPO of
# that name already there stops the op before anything is written.
# Stage 1 installs RSAT-AD-Tools, which holds no GroupPolicy module
# (MEASURED-1.5, "Stages 5 and 6 on BUILD1": Import-Module GroupPolicy
# failed), so the op installs the GPMC feature first when it is absent
# (no restart; an open point of DESIGN-1.5: stage 1 could install it).
$script:OpBodies['s6-gpo'] = @'
Import-Module ActiveDirectory
$gpmc = Get-WindowsFeature -Name GPMC
'GPMC: ' + $gpmc.InstallState
if ($gpmc.InstallState -ne 'Installed') {
    $r = Install-WindowsFeature -Name GPMC
    'Install-WindowsFeature GPMC: Success ' + $r.Success + ' RestartNeeded ' + $r.RestartNeeded + ' ExitCode ' + $r.ExitCode
}
Import-Module GroupPolicy
$dom = Get-ADDomain
$target = $dom.DistinguishedName
if ($GpoLink -ceq 'dc') { $target = $dom.DomainControllersContainer } elseif ($GpoLink -cne 'domain') { throw 'the link of the GPO is not one of the baseline' }
'domain: ' + $dom.DNSRoot + ' | target ' + $target
$before = @(Get-GPO -All | Where-Object { $_.DisplayName -ceq $GpoName })
'before: GPOs of the name: ' + $before.Count
if ($before.Count -ne 0) { throw 'a GPO of the name of the baseline GPO is there already' }
$gpo = New-GPO -Name $GpoName -Comment ('Newton AD build baseline ' + $BaselineVersion)
'New-GPO: ' + $gpo.DisplayName + ' | Id ' + $gpo.Id
foreach ($setting in $Settings) {
    $part = $setting.Split('|')
    $null = Set-GPRegistryValue -Guid $gpo.Id -Key $part[0] -ValueName $part[1] -Type DWord -Value ([int]$part[2])
    'Set-GPRegistryValue ' + $part[0] + '\' + $part[1] + ' = ' + $part[2] + ': ok'
}
$link = New-GPLink -Guid $gpo.Id -Target $target -LinkEnabled Yes
'New-GPLink: ' + $link.DisplayName + ' | Target ' + $link.Target + ' | Enabled ' + $link.Enabled + ' | Order ' + $link.Order
'read-back:'
$g = Get-GPO -Guid $gpo.Id
'  GPO ' + $g.DisplayName + ' | Id ' + $g.Id + ' | GpoStatus ' + $g.GpoStatus + ' | Computer DSVersion ' + $g.Computer.DSVersion + ' SysvolVersion ' + $g.Computer.SysvolVersion + ' | User DSVersion ' + $g.User.DSVersion + ' SysvolVersion ' + $g.User.SysvolVersion
foreach ($setting in $Settings) {
    $part = $setting.Split('|')
    $v = Get-GPRegistryValue -Guid $gpo.Id -Key $part[0] -ValueName $part[1]
    '  GPO value ' + $part[0] + '\' + $part[1] + ' = ' + $v.Value + ' | ' + $v.Type + ' | ' + $v.PolicyState
}
foreach ($l in (Get-GPInheritance -Target $target).GpoLinks) { '  link ' + $l.DisplayName + ' | Enabled ' + $l.Enabled + ' | Enforced ' + $l.Enforced + ' | Order ' + $l.Order }
'@

# Stage 6 after the GPOs: the policy applied on DC1 and read back.  The
# registry values of every baseline GPO, the Windows LAPS policy the
# domain controllers run (the policy processing and the password it
# leaves on the computer object of DC1), the secedit export of the
# security policy DC1 applies (the account policy of the domain among
# it) and the password policy of the domain, read once more after the
# refresh, so a refresh that undid stage 5's policy is seen.
$script:OpBodies['s6-read'] = @'
Import-Module ActiveDirectory
Import-Module GroupPolicy
$gp = gpupdate.exe /target:computer /force
'gpupdate /target:computer /force exit ' + $LASTEXITCODE
foreach ($line in $gp) { if ($line.Trim()) { '  gpupdate ' + $line.Trim() } }
foreach ($setting in $Settings) {
    $part = $setting.Split('|')
    $item = Get-ItemProperty -LiteralPath ('Registry::' + $part[0]) -Name $part[1] -ErrorAction SilentlyContinue
    if ($null -eq $item) { 'registry ' + $part[0] + '\' + $part[1] + ' : absent' } else { 'registry ' + $part[0] + '\' + $part[1] + ' = ' + $item.($part[1]) }
}
# Windows LAPS (AD-A-46): the policy of the Domain Controllers GPO is
# applied by the refresh above, the processing writes the password of the
# local administrator of this DC to the directory, and the read-back
# proves that the computer object of this DC carries it.  Only the time
# the password expires is read; the encrypted DSRM password is never
# printed, only whether it is there.
try {
    $null = Import-Module LAPS -ErrorAction Stop
    'LAPS module: ' + (Get-Module LAPS).Version
} catch {
    'LAPS module: absent (' + $_.Exception.Message + ')'
}
try {
    Invoke-LapsPolicyProcessing -ErrorAction Stop
    'Invoke-LapsPolicyProcessing: ok'
} catch {
    'Invoke-LapsPolicyProcessing: FAIL ' + $_.Exception.GetType().FullName + ' | ' + $_.Exception.Message
}
$computer = $null
$expiry = ''
$dsrm = 'absent'
try {
    $computer = Get-ADComputer -Identity $env:COMPUTERNAME -Properties msLAPS-PasswordExpirationTime, msLAPS-EncryptedDSRMPassword
    $expiry = [string]$computer.'msLAPS-PasswordExpirationTime'
    if ($null -ne $computer.'msLAPS-EncryptedDSRMPassword') { $dsrm = 'present' }
} catch {
    'computer object: FAIL ' + $_.Exception.GetType().FullName + ' | ' + $_.Exception.Message
}
$computer = $null
'  computer object ' + $env:COMPUTERNAME + ' | msLAPS-PasswordExpirationTime ' + $expiry + ' | msLAPS-EncryptedDSRMPassword ' + $dsrm
$cfg = 'C:\NewtonBuild\out\s6-secedit.inf'
if (Test-Path -LiteralPath $cfg) { Remove-Item -LiteralPath $cfg -Force }
$null = secedit.exe /export /cfg $cfg /areas SECURITYPOLICY /quiet
'secedit /export /areas SECURITYPOLICY exit ' + $LASTEXITCODE
foreach ($line in (Get-Content -LiteralPath $cfg -Encoding Unicode)) { 'secedit ' + $line }
Remove-Item -LiteralPath $cfg -Force
$root = (Get-ADDomain).DistinguishedName
$p = Get-ADDefaultDomainPasswordPolicy -Identity $root
'password policy: MinPasswordLength ' + $p.MinPasswordLength + ' | PasswordHistoryCount ' + $p.PasswordHistoryCount + ' | MaxPasswordAge ' + $p.MaxPasswordAge + ' | MinPasswordAge ' + $p.MinPasswordAge + ' | ComplexityEnabled ' + $p.ComplexityEnabled + ' | ReversibleEncryptionEnabled ' + $p.ReversibleEncryptionEnabled + ' | LockoutThreshold ' + $p.LockoutThreshold + ' | LockoutDuration ' + $p.LockoutDuration + ' | LockoutObservationWindow ' + $p.LockoutObservationWindow
foreach ($name in $GpoNames) { $g = Get-GPO -Name $name; 'GPO ' + $g.DisplayName + ' | GpoStatus ' + $g.GpoStatus + ' | Computer DSVersion ' + $g.Computer.DSVersion + ' SysvolVersion ' + $g.Computer.SysvolVersion }
'@

# Stage 9 on DC1: newton-build leaves Domain Admins, in the password task
# (the key login is S4U: its directory reads threw on both DCs, MEASURED-1.5
# "Stage 9 on BUILD2, then BUILD1"; this op's removal is unmeasured,
# DESIGN-1.5 open point 18 of task 8).  The membership is read through the
# group, not Get-ADPrincipalGroupMembership (the read that threw).
# ---------------------------------------------------------------------------
# stage 7, option B (the maintainer, 2026-11-11; MEASURED-1.5 "Stage 7 on BUILD1 and
# BUILD2, 2026-11-15"; the maintainer's decisions K16, K17 and K19, 2026-11-15)
#
# DC1 makes three runs under one stage token, each the phase after the one
# its own journal records (K19): s7-provision (djoin /provision, in its
# password task, Kerberos; the blob goes back in the run's answer, never to
# the journal), s7-install (Install-ADDSDomainController on DC2 over WinRM
# with Kerberos from the same password task, then DC2's restart in that
# session) and s7-read (repadmin /showrepl both ways and dcdiag on both,
# polled up to 30 minutes, K17; never a forced KCC or sync).  DC2 makes one
# run, s7-join (djoin /requestODJ in its key login, then the reboot); its
# status after that boot reads it a member (s7-member), and after the
# promotion's boot reads it a DC and rotates its machine password, which
# the blob carried (s7-dc, K16).
# ---------------------------------------------------------------------------

# DC1, the password task: the provision of DC2's computer object and the
# offline domain join blob.  The lines are the measured ones; a computer
# object already there stops the op before djoin unless the run is a resume
# plan's (Reuse '1'), which provisions it again with /reuse.
$script:OpBodies['s7-provision'] = @'
$Blob = $BlobFile
if (Test-Path -LiteralPath $Blob) { Remove-Item -LiteralPath $Blob -Force }
'before: ' + $(try { (Get-ADComputer -Identity $Dc2Host -ErrorAction Stop).DistinguishedName } catch { 'no computer ' + $Dc2Host + ' (' + $_.Exception.GetType().FullName + ')' })
$exists = $true
try { $null = Get-ADComputer -Identity $Dc2Host -ErrorAction Stop } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $exists = $false }
$argv = @('/provision', '/domain', $DnsName, '/machine', $Dc2Host, '/savefile', $Blob)
if ($exists) {
    if ($Reuse -cne '1') { throw 'the computer object of DC2 is there already, and this run is not a resume' }
    $argv = $argv + @('/reuse')
}
'djoin argv: ' + ($argv -join ' ')
$sw = [Diagnostics.Stopwatch]::StartNew()
$o = @(& djoin.exe @argv 2>&1)
'djoin /provision exit ' + $LASTEXITCODE + ' in ' + [int]$sw.Elapsed.TotalSeconds + ' s, ' + $o.Count + ' lines:'
$o | ForEach-Object { '  [' + [string]$_ + ']' }
$item = Get-Item -LiteralPath $Blob
'blob: ' + $item.FullName + ', bytes ' + $item.Length
$all = [IO.File]::ReadAllBytes($Blob)
'blob first two bytes: ' + $all[0].ToString('x2') + ' ' + $all[1].ToString('x2')
$all = $null
$acl = Get-Acl -LiteralPath $Blob
'blob owner: ' + $acl.Owner + ' | protected ' + $acl.AreAccessRulesProtected
$acl.Access | ForEach-Object { '  ace: ' + $_.IdentityReference + ' ' + $_.AccessControlType + ' ' + $_.FileSystemRights + ' inherited ' + $_.IsInherited }
$c = Get-ADComputer -Identity $Dc2Host -Properties whenCreated, userAccountControl, primaryGroupID, servicePrincipalName, pwdLastSet, dNSHostName
'computer: ' + $c.DistinguishedName + ' | userAccountControl ' + $c.userAccountControl + ' | primaryGroupID ' + $c.primaryGroupID + ' | pwdLastSet ' + $c.pwdLastSet + ' | dNSHostName ' + $c.dNSHostName
'SPN: ' + (($c.servicePrincipalName | Sort-Object) -join ', ')
'@

# DC1, the password task: WinRM to DC2 with Kerberos, then, in that
# session, the replica's promotion with the build account's credential from
# DC1's pw.bin and DC2's own DSRM file (both stay inside the two DCs), then
# DC2's restart in the same session once the promotion asks for it.  The
# lines are the measured ones; the Test-WSMan line is the measured check of
# m7-wsman, and the restart line is new (measured from DC2's key login only).
$script:OpBodies['s7-install'] = @'
Add-Type -AssemblyName System.Security
$t = Test-WSMan -ComputerName $Dc2Fqdn -Authentication Kerberos -ErrorAction Stop
'Test-WSMan Kerberos: ProductVersion ' + $t.ProductVersion
$c0 = Get-ADComputer -Identity $Dc2Host -Properties pwdLastSet, userAccountControl, primaryGroupID
'before: ' + $c0.DistinguishedName + ' | pwdLastSet ' + $c0.pwdLastSet + ' | userAccountControl ' + $c0.userAccountControl + ' | primaryGroupID ' + $c0.primaryGroupID
$cred = New-Object System.Management.Automation.PSCredential (($Netbios + '\' + $BuildUser), (ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes('C:\NewtonBuild\pw.bin'), $null, 'LocalMachine'))) -AsPlainText -Force))
$sw = [Diagnostics.Stopwatch]::StartNew()
$r = Invoke-Command -ComputerName $Dc2Fqdn -Authentication Kerberos -ErrorAction Stop -ArgumentList $cred, $DnsName, $SiteName -ScriptBlock {
  param($Credential, $Domain, $Site)
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  Add-Type -AssemblyName System.Security
  $f = 'C:\NewtonBuild\dsrm.bin'
  $sec = ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($f), $null, 'LocalMachine'))) -AsPlainText -Force
  Remove-Item -LiteralPath $f; 'dsrm.bin deleted on ' + $env:COMPUTERNAME + ': ' + (-not (Test-Path -LiteralPath $f))
  'remote identity: ' + (whoami) + ' | auth ' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $x = Install-ADDSDomainController -DomainName $Domain -SiteName $Site -InstallDns -Credential $Credential -SafeModeAdministratorPassword $sec -NoRebootOnCompletion -Force
  'Install-ADDSDomainController returned after ' + [int]$sw.Elapsed.TotalSeconds + ' s'
  $x | Format-List * | Out-String -Width 250
  if (([string]$x.Status -eq 'Success') -and [bool]$x.RebootRequired) {
    $null = & shutdown.exe /r /t 10
    'shutdown /r /t 10 on ' + $env:COMPUTERNAME + ' exit ' + $LASTEXITCODE
  }
}
$cred = $null
$r | ForEach-Object { [string]$_ }
'Invoke-Command returned after ' + [int]$sw.Elapsed.TotalSeconds + ' s'
$c1 = Get-ADComputer -Identity $Dc2Host -Properties pwdLastSet, userAccountControl, primaryGroupID
'after: ' + $c1.DistinguishedName + ' | pwdLastSet ' + $c1.pwdLastSet + ' | userAccountControl ' + $c1.userAccountControl + ' | primaryGroupID ' + $c1.primaryGroupID
'@

# DC1, the password task: the replication read-back (the maintainer's decision K17):
# repadmin /showrepl * /csv every ReadPollSeconds until both DCs replicate
# every naming context from the other with 0 failures (a failure older than
# this read-back's start less 2 minutes is accepted when a later success of
# the same naming context exists and a later poll shows the row unchanged:
# the schema does not change, so nothing clears the row DC2's boot left,
# and nothing is accepted on the first poll alone; a row seen clean that
# fails again is never accepted, even with the same count and time: the maintainer,
# 2026-11-22) and dcdiag on DC1 (the
# full form) shows every test of the list passed and none failed but the
# accepted pair, at most ReadWaitSeconds (30 minutes, or less when the
# token's bound is nearer).
# DC2's genid and DC2's dcdiag are DC2's own reads (s7-dc): msDS-GenerationId
# is not replicated, and dcdiag /s: from DC1 fails 0x6ba on the remote event
# log (open point 77, ruled 2026-11-21).  Nothing is forced: no
# repadmin /kcc, no /syncall.  The read-back block at the end is what the
# helper parses.
$script:OpBodies['s7-read'] = @'
Import-Module ActiveDirectory
$dn = (Get-ADDomain).DistinguishedName
$ncs = @($dn, ('CN=Configuration,' + $dn), ('CN=Schema,CN=Configuration,' + $dn), ('DC=DomainDnsZones,' + $dn), ('DC=ForestDnsZones,' + $dn))
$header = 'kind', 'dsite', 'dest', 'nc', 'ssite', 'src', 'transport', 'failures', 'lastfail', 'lastsuccess', 'status'
$startedText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
$cutoff = [DateTime]::ParseExact($startedText, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
function ConvertTo-NewtonRepadminTime([string]$Text) {
    $at = [DateTime]::MinValue
    if ([DateTime]::TryParseExact($Text, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$at)) { return $at }
    return $null
}
# A row with a failure is accepted only when all three hold (the maintainer's decision
# of 2026-11-21 on open point 77, refined): its last failure is older than
# this read-back's start less 2 minutes, some row of the same naming
# context (either direction) shows 0 failures and a success after it, and a
# LATER poll shows the row unchanged (the same failure count and the same
# failure time).  So the first poll that sees such a row only records it
# ($seen), never accepts it, and a row that changes after it was recorded is
# never accepted ($bad).
# A row that was seen clean and fails again is a new failure and is never
# accepted either: the clean rows of every poll are recorded ($clean) before
# any row of that poll is judged, so a poll that returns early for another
# row or for another naming context does not hide that a row was clean.
$window = $cutoff.AddMinutes(-2)
$seen = @{}
$bad = @{}
$clean = @{}
$script:fresh = $false
$script:confirmed = $false
function Test-NewtonOldFailure($Row, $NcRows) {
    $failed = ConvertTo-NewtonRepadminTime ([string]$Row.lastfail)
    if (($null -eq $failed) -or ($failed -ge $window)) { return $false }
    foreach ($other in $NcRows) {
        if (([string]$other.failures -ne '0') -or ([string]$other.status -ne '0')) { continue }
        $success = ConvertTo-NewtonRepadminTime ([string]$other.lastsuccess)
        if (($null -ne $success) -and ($success -gt $failed)) { return $true }
    }
    return $false
}
function Test-NewtonReplicaRows($Rows) {
    $script:fresh = $false
    if (@($Rows | Where-Object { $_ -like 'showrepl_ERROR*' }).Count -ne 0) { return $false }
    $data = @($Rows | Where-Object { $_ -like 'showrepl_INFO,*' } | ConvertFrom-Csv -Header $header)
    # The clean rows of this poll are recorded before any row of it is
    # judged: a poll that returns early for another row or for another
    # naming context must not hide that a row was clean.
    foreach ($pair in @(@($Dc1Host, $Dc2Host), @($Dc2Host, $Dc1Host))) {
        $mine = @($data | Where-Object { ($_.dest -eq $pair[0]) -and ($_.src -eq $pair[1]) })
        foreach ($nc in $ncs) {
            $row = @($mine | Where-Object { $_.nc -eq $nc })
            if ($row.Count -ne 1) { continue }
            if (($row[0].failures -eq '0') -and ($row[0].status -eq '0')) {
                $clean[$pair[0] + '|' + $pair[1] + '|' + $nc] = $true
            }
        }
    }
    foreach ($pair in @(@($Dc1Host, $Dc2Host), @($Dc2Host, $Dc1Host))) {
        $mine = @($data | Where-Object { ($_.dest -eq $pair[0]) -and ($_.src -eq $pair[1]) })
        if ($mine.Count -ne $ncs.Count) { return $false }
        foreach ($nc in $ncs) {
            $row = @($mine | Where-Object { $_.nc -eq $nc })
            if ($row.Count -ne 1) { return $false }
            $key = $pair[0] + '|' + $pair[1] + '|' + $nc
            if (($row[0].failures -ne '0') -or ($row[0].status -ne '0')) {
                if (-not (Test-NewtonOldFailure $row[0] @($data | Where-Object { $_.nc -eq $nc }))) { return $false }
                $signature = [string]$row[0].failures + '|' + [string]$row[0].lastfail
                if ($bad.ContainsKey($key)) { return $false }
                # Seen clean, failing again: never accepted, even with the same
                # count and time (point 77, strict).
                if ($clean.ContainsKey($key)) { $bad[$key] = $true; return $false }
                if ($seen.ContainsKey($key) -and ($seen[$key] -ne $signature)) { $bad[$key] = $true; return $false }
                if (-not $seen.ContainsKey($key)) { $seen[$key] = $signature; $script:fresh = $true }
            }
        }
    }
    if ($script:fresh) { return $false }
    if ($seen.Count -gt 0) { $script:confirmed = $true }
    return $true
}
# dcdiag in its full form: /q prints no line for a test that passed, so
# only the full form shows a test ran.  Converged needs exit 0 and every
# test of the helper's list passed by that DC (the server tests) or by
# any subject (the partition and enterprise tests), and no failed test
# but DFSREvent and SystemLog (X3 of a review).
function Test-NewtonDcdiagOk($Lines, $Rc, [string]$Server) {
    if ($Rc -ne 0) { return $false }
    $must = @('Connectivity', 'Advertising', 'FrsEvent', 'SysVolCheck', 'KccEvent',
        'KnowsOfRoleHolders', 'MachineAccount', 'NCSecDesc', 'NetLogons',
        'ObjectsReplicated', 'Replications', 'RidManager', 'Services',
        'VerifyReferences', 'CheckSDRefDom', 'CrossRefValidation',
        'LocatorCheck', 'Intersite')
    $any = @('CheckSDRefDom', 'CrossRefValidation', 'LocatorCheck', 'Intersite')
    $passed = @{}
    foreach ($line in $Lines) {
        if ([string]$line -cmatch '\A\s*\.{5,} (\S+) (passed|failed) test ?(\S*)\s*\z') {
            if ($Matches[2] -ceq 'failed') {
                if (@('DFSREvent', 'SystemLog') -cnotcontains $Matches[3]) { return $false }
            } elseif ($Matches[3] -ne '') {
                if ($Matches[1] -eq $Server) { $passed['server ' + $Matches[3]] = $true }
                $passed['any ' + $Matches[3]] = $true
            }
        }
    }
    foreach ($test in $must) {
        $key = 'server ' + $test
        if ($any -ccontains $test) { $key = 'any ' + $test }
        if (-not $passed.ContainsKey($key)) { return $false }
    }
    return $true
}
$sw = [Diagnostics.Stopwatch]::StartNew()
$poll = 0; $rows = @(); $rc = -1; $dd1 = @(); $dd1rc = -1; $diag = $false; $converged = $false
$ErrorActionPreference = 'Continue'
while ($true) {
    $poll = $poll + 1
    $rows = @(& repadmin.exe /showrepl * /csv 2>&1 | ForEach-Object { [string]$_ })
    $rc = $LASTEXITCODE
    'poll ' + $poll + ' at ' + (Get-Date).ToUniversalTime().ToString('o') + ', ' + [int]$sw.Elapsed.TotalSeconds + ' s: repadmin /showrepl * /csv exit ' + $rc + ', ' + $rows.Count + ' lines'
    if (($rc -eq 0) -and (Test-NewtonReplicaRows $rows)) {
        $dd1 = @(& dcdiag.exe 2>&1 | ForEach-Object { [string]$_ }); $dd1rc = $LASTEXITCODE
        $diag = $true
        $diagOk = Test-NewtonDcdiagOk $dd1 $dd1rc $Dc1Host
        '  replication 0 failures both ways; dcdiag on DC1: exit ' + $dd1rc + ', passed ' + $diagOk
        if ($diagOk) { $converged = $true; break }
    }
    if ($sw.Elapsed.TotalSeconds -ge [int]$ReadWaitSeconds) { break }
    Start-Sleep -Seconds ([int]$ReadPollSeconds)
}
if (-not $diag) {
    $dd1 = @(& dcdiag.exe 2>&1 | ForEach-Object { [string]$_ }); $dd1rc = $LASTEXITCODE
}
$ErrorActionPreference = 'Stop'
'read-back after ' + [int]$sw.Elapsed.TotalSeconds + ' s, ' + $poll + ' polls, converged ' + $converged
'read-back started: ' + $startedText
'old failures confirmed: ' + $script:confirmed
'repadmin /showrepl * /csv exit ' + $rc + ', ' + $rows.Count + ' lines:'
$rows | ForEach-Object { '  ' + $_ }
'dcdiag exit ' + $dd1rc + ', ' + $dd1.Count + ' lines:'
$dd1 | ForEach-Object { '  ' + $_ }
Get-ADDomainController -Filter * | Sort-Object Name | ForEach-Object { 'DC ' + $_.Name + ' | GC ' + $_.IsGlobalCatalog + ' | RODC ' + $_.IsReadOnly + ' | site ' + $_.Site }
'@

# DC2, the key login (the local newton-build, NTLM): DNS to DC1, then
# djoin /requestODJ with the blob the helper wrote from the request.  The
# lines are the measured ones.
$script:OpBodies['s7-join'] = @'
$Blob = $BlobFile
$address = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq $Ip }
'dns client before: ' + ((Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $address.InterfaceIndex).ServerAddresses -join ',')
Set-DnsClientServerAddress -InterfaceIndex $address.InterfaceIndex -ServerAddresses @($Dc1Ip)
'dns client: ' + ((Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $address.InterfaceIndex).ServerAddresses -join ',')
'resolve ' + $DnsName + ': ' + $(try { ((Resolve-DnsName -Name $DnsName -Type A -DnsOnly -ErrorAction Stop | Where-Object Type -eq 'A' | ForEach-Object IPAddress) -join ',') } catch { 'FAIL ' + $_.Exception.Message })
'srv: ' + $(try { ((Resolve-DnsName -Name ('_ldap._tcp.dc._msdcs.' + $DnsName) -Type SRV -DnsOnly -ErrorAction Stop | Where-Object Type -eq 'SRV' | ForEach-Object NameTarget) -join ',') } catch { 'FAIL ' + $_.Exception.Message })
'blob: bytes ' + (Get-Item -LiteralPath $Blob).Length
$sw = [Diagnostics.Stopwatch]::StartNew()
$o = @(& djoin.exe /requestODJ /loadfile $Blob /windowspath $env:SystemRoot /localos 2>&1)
'djoin /requestODJ exit ' + $LASTEXITCODE + ' in ' + [int]$sw.Elapsed.TotalSeconds + ' s, ' + $o.Count + ' lines:'
$o | ForEach-Object { '  [' + [string]$_ + ']' }
Remove-Item -LiteralPath $Blob -Force; 'blob deleted: ' + (-not (Test-Path -LiteralPath $Blob))
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
'cs before the reboot: Name ' + $cs.Name + ' | DomainRole ' + $cs.DomainRole + ' | PartOfDomain ' + $cs.PartOfDomain + ' | Domain ' + $cs.Domain
'@

# DC2, the key login after the join's boot: a member of the domain
# (measured: DomainRole 3, PartOfDomain True, the network profile
# DomainAuthenticated).
$script:OpBodies['s7-member'] = @'
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
'cs: Name ' + $cs.Name + ' | DomainRole ' + $cs.DomainRole + ' | PartOfDomain ' + $cs.PartOfDomain + ' | Domain ' + $cs.Domain
'network profile: ' + ((Get-NetConnectionProfile | ForEach-Object { [string]$_.NetworkCategory }) -join ',')
'LastBootUpTime: ' + (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
'@

# DC2, the key login after the promotion's boot (now the domain
# newton-build, S4U): a DC with msDS-GenerationId on its computer object,
# then its machine password rotated (the maintainer's decision K16: the blob carried the
# old one) and read back: pwdLastSet advanced past the promotion's boot,
# and the secure channel holds (nltest /sc_verify).  Reset-ComputerMachinePassword
# in this login was measured (MEASURED-1.5, stage 7); nltest was not.
$script:OpBodies['s7-dc'] = @'
Import-Module ActiveDirectory
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
'cs: Name ' + $cs.Name + ' | DomainRole ' + $cs.DomainRole + ' | PartOfDomain ' + $cs.PartOfDomain + ' | Domain ' + $cs.Domain
'LastBootUpTime: ' + (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
# A DC2 that booted by itself before DC1's install is a member: its
# machine password is not rotated.  Only a replica DC (DomainRole 4, what
# the parser requires) goes on (IC-L1 of a review).
if ([int]$cs.DomainRole -ne 4) { throw ('this server is not a replica domain controller (DomainRole ' + $cs.DomainRole + '); the machine password is not reset') }
$c = Get-ADComputer -Identity $env:COMPUTERNAME -Properties msDS-GenerationId, pwdLastSet -Server $env:COMPUTERNAME
$g = $c.'msDS-GenerationId'
'msDS-GenerationId on ' + $c.DistinguishedName + ': ' + $(if ($g) { 'present, ' + $g.Length + ' bytes, ' + (($g | ForEach-Object { $_.ToString('x2') }) -join '') } else { 'absent' })
'pwdLastSet before the reset: ' + $c.pwdLastSet
Reset-ComputerMachinePassword -ErrorAction Stop
'Reset-ComputerMachinePassword: ok'
Start-Sleep -Seconds 5
$c = Get-ADComputer -Identity $env:COMPUTERNAME -Properties pwdLastSet -Server $env:COMPUTERNAME
'pwdLastSet after the reset: ' + $c.pwdLastSet + ' | ' + [DateTime]::FromFileTimeUtc([int64]$c.pwdLastSet).ToString('o')
# The secure channel: nltest /sc_verify of the plan's domain, the tool
# Microsoft documents for a DC.  Test-ComputerSecureChannel is not run: its
# reference says it "only works on Domain Member computers" and "returns
# false positive errors" on a DC (F3 of a review).
$ErrorActionPreference = 'Continue'
$nl = @(& nltest.exe ('/sc_verify:' + $DnsName) 2>&1 | ForEach-Object { [string]$_ })
'nltest /sc_verify exit ' + $LASTEXITCODE + ', ' + $nl.Count + ' lines:'
$nl | ForEach-Object { '  ' + $_ }
# dcdiag runs on this DC itself (open point 77, ruled 2026-11-21): from DC1,
# dcdiag /s: fails 0x6ba on the remote event log.  The full form, read again
# every DiagPollSeconds until every test of the list passed and none failed
# but the accepted pair, at most DiagWaitSeconds: the promotion's first
# replication may not have settled yet.  Nothing is forced.
# The Replications test may fail as well, but only under the maintainer's
# old-row rule (2026-11-23): the failing rows of repadmin /showrepl * /csv
# are accepted only when they are older than this read's start less two
# minutes, a row of the same naming context in either direction shows 0
# failures and a success after them, and a LATER poll shows them unchanged.
# So the op reads repadmin /showrepl * /csv on every poll and prints the
# last poll's rows: the parser reads them back (Get-NewtonStage7DcVerdict).
$dn = (Get-ADDomain).DistinguishedName
$ncs = @($dn, ('CN=Configuration,' + $dn), ('CN=Schema,CN=Configuration,' + $dn), ('DC=DomainDnsZones,' + $dn), ('DC=ForestDnsZones,' + $dn))
$header = 'kind', 'dsite', 'dest', 'nc', 'ssite', 'src', 'transport', 'failures', 'lastfail', 'lastsuccess', 'status'
$startedText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
$cutoff = [DateTime]::ParseExact($startedText, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
function ConvertTo-NewtonRepadminTime([string]$Text) {
    $at = [DateTime]::MinValue
    if ([DateTime]::TryParseExact($Text, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$at)) { return $at }
    return $null
}
# The rule of the s7-read op, the same three conditions (the maintainer's
# decision of 2026-11-21 on open point 77, refined): the last failure of
# the row is older than this read's start less 2 minutes, some row of the
# same naming context (either direction) shows 0 failures and a success
# after it, and a LATER poll shows the row unchanged (the same failure
# count and the same failure time).  So the first poll that sees such a
# row only records it ($seen), never accepts it, and a row that changes
# after it was recorded is never accepted ($bad).
# A row that was seen clean and fails again is a new failure and is never
# accepted either: the clean rows of every poll are recorded ($clean)
# before any row of that poll is judged, so a poll that returns early for
# another row or for another naming context does not hide that a row was
# clean.
# The rule of THIS pass (the maintainer's rule of 2026-11-24): a failed
# Replications test is accepted only on a pass that holds at least one
# failing row, every failing row of that pass accepted by the rule above
# and recorded with the same signature (the failure count and the failure
# time) on an EARLIER pass, and no row of that pass ever seen clean and
# then failing.  So the confirmation does not outlive the failing row: a
# pass that shows every row clean holds no old failure at all, and the
# dcdiag failed for another reason.  $script:oldRowsNow says so of the
# pass being judged, and $script:confirmed is what the read-back prints.
$window = $cutoff.AddMinutes(-2)
$seen = @{}
$bad = @{}
$clean = @{}
$script:fresh = $false
$script:confirmed = $false
$script:oldRowsNow = $false
function Test-NewtonOldFailure($Row, $NcRows) {
    $failed = ConvertTo-NewtonRepadminTime ([string]$Row.lastfail)
    if (($null -eq $failed) -or ($failed -ge $window)) { return $false }
    foreach ($other in $NcRows) {
        if (([string]$other.failures -ne '0') -or ([string]$other.status -ne '0')) { continue }
        $success = ConvertTo-NewtonRepadminTime ([string]$other.lastsuccess)
        if (($null -ne $success) -and ($success -gt $failed)) { return $true }
    }
    return $false
}
function Test-NewtonReplicaRows($Rows) {
    $script:fresh = $false
    $script:oldRowsNow = $false
    $oldNow = $false
    if (@($Rows | Where-Object { $_ -like 'showrepl_ERROR*' }).Count -ne 0) { return $false }
    $data = @($Rows | Where-Object { $_ -like 'showrepl_INFO,*' } | ConvertFrom-Csv -Header $header)
    # The clean rows of this poll are recorded before any row of it is
    # judged: a poll that returns early for another row or for another
    # naming context must not hide that a row was clean.
    foreach ($pair in @(@($Dc1Host, $Dc2Host), @($Dc2Host, $Dc1Host))) {
        $mine = @($data | Where-Object { ($_.dest -eq $pair[0]) -and ($_.src -eq $pair[1]) })
        foreach ($nc in $ncs) {
            $row = @($mine | Where-Object { $_.nc -eq $nc })
            if ($row.Count -ne 1) { continue }
            if (($row[0].failures -eq '0') -and ($row[0].status -eq '0')) {
                $clean[$pair[0] + '|' + $pair[1] + '|' + $nc] = $true
            }
        }
    }
    foreach ($pair in @(@($Dc1Host, $Dc2Host), @($Dc2Host, $Dc1Host))) {
        $mine = @($data | Where-Object { ($_.dest -eq $pair[0]) -and ($_.src -eq $pair[1]) })
        if ($mine.Count -ne $ncs.Count) { return $false }
        foreach ($nc in $ncs) {
            $row = @($mine | Where-Object { $_.nc -eq $nc })
            if ($row.Count -ne 1) { return $false }
            $key = $pair[0] + '|' + $pair[1] + '|' + $nc
            if (($row[0].failures -ne '0') -or ($row[0].status -ne '0')) {
                if (-not (Test-NewtonOldFailure $row[0] @($data | Where-Object { $_.nc -eq $nc }))) { return $false }
                $signature = [string]$row[0].failures + '|' + [string]$row[0].lastfail
                if ($bad.ContainsKey($key)) { return $false }
                # Seen clean, failing again: never accepted, even with the same
                # count and time (point 77, strict).
                if ($clean.ContainsKey($key)) { $bad[$key] = $true; return $false }
                if ($seen.ContainsKey($key)) {
                    if ($seen[$key] -ne $signature) { $bad[$key] = $true; return $false }
                    # Recorded on an EARLIER pass with the same signature: this
                    # pass holds an old failure the rule accepts.
                    $oldNow = $true
                } else {
                    $seen[$key] = $signature; $script:fresh = $true
                }
            }
        }
    }
    if ($script:fresh) { return $false }
    # This pass holds an old failure the rule accepts: the dcdiag of this
    # pass may fail Replications, and only then.
    $script:oldRowsNow = $oldNow
    $script:confirmed = $oldNow
    return $true
}

# The dcdiag of this DC: every test of the list passed by it, and none
# failed but the accepted pair.  The Replications test may fail as well
# when the old-row rule accepted the failing rows of repadmin (and a later
# poll confirmed them): $OldRowsOk says so.
function Test-NewtonDcdiagOk($Lines, $Rc, [string]$Server, [bool]$OldRowsOk) {
    if ($Rc -ne 0) { return $false }
    $must = @('Connectivity', 'Advertising', 'FrsEvent', 'SysVolCheck', 'KccEvent',
        'KnowsOfRoleHolders', 'MachineAccount', 'NCSecDesc', 'NetLogons',
        'ObjectsReplicated', 'Replications', 'RidManager', 'Services',
        'VerifyReferences', 'CheckSDRefDom', 'CrossRefValidation',
        'LocatorCheck', 'Intersite')
    $any = @('CheckSDRefDom', 'CrossRefValidation', 'LocatorCheck', 'Intersite')
    $passed = @{}
    $oldFailure = $false
    foreach ($line in $Lines) {
        if ([string]$line -cmatch '\A\s*\.{5,} (\S+) (passed|failed) test ?(\S*)\s*\z') {
            if ($Matches[2] -ceq 'failed') {
                if ($Matches[3] -ceq 'Replications') {
                    if ($OldRowsOk -and ($Matches[1] -eq $Server)) { $oldFailure = $true; continue }
                }
                if (@('DFSREvent', 'SystemLog') -cnotcontains $Matches[3]) { return $false }
            } elseif ($Matches[3] -ne '') {
                if ($Matches[1] -eq $Server) { $passed['server ' + $Matches[3]] = $true }
                $passed['any ' + $Matches[3]] = $true
            }
        }
    }
    foreach ($test in $must) {
        $key = 'server ' + $test
        if ($any -ccontains $test) { $key = 'any ' + $test }
        if (-not $passed.ContainsKey($key)) {
            # The Replications test ran and its failure is the accepted one.
            if (($test -ceq 'Replications') -and $oldFailure) { continue }
            return $false
        }
    }
    return $true
}
$ErrorActionPreference = 'Continue'
$sw = [Diagnostics.Stopwatch]::StartNew()
$poll = 0; $rows = @(); $rc = -1; $dd = @(); $ddrc = -1; $converged = $false
while ($true) {
    # The wait is a hard limit: no pass starts once it is spent, and a pass
    # that starts with seconds left may end after it (the margin of one
    # pass the token's bound leaves is what pays for that).
    if ($sw.Elapsed.TotalSeconds -ge [double]$DiagWaitSeconds) { break }
    $poll = $poll + 1
    # The rule of this pass alone: a pass that holds no failing row holds no
    # old failure, whatever an earlier pass saw.
    $script:oldRowsNow = $false
    $script:confirmed = $false
    $rows = @(& repadmin.exe /showrepl * /csv 2>&1 | ForEach-Object { [string]$_ })
    $rc = $LASTEXITCODE
    'poll ' + $poll + ' at ' + (Get-Date).ToUniversalTime().ToString('o') + ', ' + [int]$sw.Elapsed.TotalSeconds + ' s: repadmin /showrepl * /csv exit ' + $rc + ', ' + $rows.Count + ' lines'
    $rowsOk = $false
    if ($rc -eq 0) { $rowsOk = Test-NewtonReplicaRows $rows }
    $dd = @(& dcdiag.exe 2>&1 | ForEach-Object { [string]$_ }); $ddrc = $LASTEXITCODE
    if (Test-NewtonDcdiagOk $dd $ddrc $Dc2Host ($rowsOk -and $script:oldRowsNow)) { $converged = $true; break }
    # The sleep is the shorter of the poll and the time left.
    $left = [double]$DiagWaitSeconds - $sw.Elapsed.TotalSeconds
    if ($left -le 0) { break }
    $nap = [Math]::Min([double]$DiagPollSeconds, $left)
    Start-Sleep -Milliseconds ([int]($nap * 1000))
}
$ErrorActionPreference = 'Stop'
'read-back after ' + [int]$sw.Elapsed.TotalSeconds + ' s, ' + $poll + ' polls, converged ' + $converged
'read-back started: ' + $startedText
'old failures confirmed: ' + $script:confirmed
'repadmin /showrepl * /csv exit ' + $rc + ', ' + $rows.Count + ' lines:'
$rows | ForEach-Object { '  ' + $_ }
'dcdiag exit ' + $ddrc + ', ' + $dd.Count + ' lines:'
$dd | ForEach-Object { '  ' + $_ }
'@

$script:OpBodies['s9-da'] = @'
Import-Module ActiveDirectory
$before = @(Get-ADGroupMember -Identity 'Domain Admins' | Where-Object { $_.SamAccountName -eq $BuildUser }).Count
'member before: ' + $before
if ($before -gt 0) {
    Remove-ADGroupMember -Identity 'Domain Admins' -Members $BuildUser -Confirm:$false
    'Remove-ADGroupMember Domain Admins ' + $BuildUser + ': ok'
}
$after = @(Get-ADGroupMember -Identity 'Domain Admins' | Where-Object { $_.SamAccountName -eq $BuildUser }).Count
'member after: ' + $after
'@

# Stage 9 on both: the one-shot SYSTEM task of the cleanup, registered from
# the key login and started (measured on both DCs).  The script is the
# helper's own render (Get-NewtonCleanupScript), carried as base64.
$script:OpBodies['s9-register'] = @'
$dir = Split-Path -Parent $CleanupScript
if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir }
[IO.File]::WriteAllText($CleanupScript, [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CleanupB64)), (New-Object System.Text.UTF8Encoding $true))
'cleanup script: ' + $CleanupScript + ', bytes ' + (Get-Item -LiteralPath $CleanupScript).Length
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + $CleanupScript)
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$t = Register-ScheduledTask -TaskName $CleanupTask -Action $action -Settings $settings -Principal $principal
'registered ' + $t.TaskName + ' as ' + $t.Principal.UserId + ' LogonType ' + $t.Principal.LogonType
Start-ScheduledTask -TaskName $CleanupTask
Start-Sleep -Seconds 2
'state ' + (Get-ScheduledTask -TaskName $CleanupTask).State
'@

# The cleanup of stage 9 (DESIGN-1.5 "Stage graphs", measured on both DCs):
# after a wait that lets the helper's answer leave, the build account's own
# block (the bootstrap's marker line, its Match line and the indented lines
# under it) leaves the sshd configuration and nothing else does: the
# bootstrap's backup is never restored, so the newton-ops and newton-audit
# blocks stage 8 wrote stay (the maintainer's decision on open point 37, 2026-11-16).
# A configuration sshd refuses after the removal is put back as it was
# before the cleanup.  Then sshd restarts, the keys file,
# the helper, K and pw.bin (and a DSRM file a stage 7 never consumed) are
# deleted; on DC1 the domain account newton-build goes last.  Each step is
# logged; a step that fails does not stop the next.
$script:CleanupDelaySeconds = 15
$script:CleanupScriptPath = 'C:\ProgramData\Newton\ad-build-cleanup.ps1'
$script:CleanupLogPath = 'C:\ProgramData\Newton\ad-build-cleanup.txt'
$script:CleanupTaskName = 'NewtonBuild-cleanup'
$script:SshdConfigPath = 'C:\ProgramData\ssh\sshd_config'
# The bootstrap's marker line of the build account's sshd block
# (bootstrap.BLOCK_MARKER).
$script:BuildBlockMarker = '# newton-ad build'
$script:CleanupBody = @'
$ErrorActionPreference = 'Continue'
function W([string]$t) { [IO.File]::AppendAllText($Log, ((Get-Date).ToUniversalTime().ToString('o') + ' ' + $t + "`r`n")) }
Start-Sleep -Seconds $Delay
W ('identity ' + (whoami))
$sshdOld = $null
try {
    $sshdOld = [IO.File]::ReadAllText($SshdConfig)
    $kept = New-Object System.Collections.ArrayList
    $inBlock = $false
    $removed = 0
    foreach ($line in ($sshdOld -split "`r?`n")) {
        if ($line -ceq $BlockMarker) { $inBlock = $true; $removed++; continue }
        if ($inBlock -and ($line -match '^\s*Match\s+User\s+' + [regex]::Escape($BuildUser) + ',')) { $removed++; continue }
        if ($inBlock -and ($line -match '^\s+\S') -and ($line -notmatch '^\s*Match\s')) { $removed++; continue }
        $inBlock = $false
        [void]$kept.Add($line)
    }
    while (($kept.Count -gt 0) -and ([string]$kept[$kept.Count - 1] -eq '')) { $kept.RemoveAt($kept.Count - 1) }
    [IO.File]::WriteAllText($SshdConfig, ((@($kept) -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding $false))
    W ('sshd_config: the build block removed, ' + $removed + ' line(s); the backup is not restored')
} catch { W ('FAIL remove the build block: ' + $_.Exception.Message) }
$sshdTest = 1
try { $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'; $null = & $sshd -t 2>&1; $sshdTest = $LASTEXITCODE; W ('sshd -t exit ' + $sshdTest) } catch { W ('FAIL sshd -t: ' + $_.Exception.Message) }
if (($sshdTest -ne 0) -and ($null -ne $sshdOld)) {
    try { [IO.File]::WriteAllText($SshdConfig, $sshdOld, (New-Object System.Text.UTF8Encoding $false)); W 'sshd refused the configuration: the one before the cleanup is put back' } catch { W ('FAIL put back: ' + $_.Exception.Message) }
}
try { Restart-Service -Name sshd -Force -ErrorAction Stop; W ('sshd restarted: ' + (Get-Service -Name sshd).Status) } catch { W ('FAIL sshd restart: ' + $_.Exception.Message) }
foreach ($p in $Files) {
    try { Remove-Item -LiteralPath $p -Force -ErrorAction Stop; W ('deleted ' + $p + ': ' + (-not (Test-Path -LiteralPath $p))) } catch { W ('FAIL delete ' + $p + ': ' + $_.Exception.GetType().FullName) }
}
try { Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction Stop; W 'task unregistered' } catch { W ('FAIL unregister: ' + $_.Exception.Message) }
try { Remove-Item -LiteralPath $Self -Force -ErrorAction Stop; W 'cleanup script deleted' } catch { W ('FAIL delete script: ' + $_.Exception.Message) }
W 'end'
'@

# DC1's only: the domain account, after every file of Newton's access.
$script:CleanupAccountBody = @'
try { Import-Module ActiveDirectory -ErrorAction Stop; Remove-ADUser -Identity $BuildUser -Confirm:$false -ErrorAction Stop; W ('Remove-ADUser ' + $BuildUser + ': ok') } catch { W ('FAIL Remove-ADUser: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message) }
try { $null = Get-ADUser -Identity $BuildUser -ErrorAction Stop; W 'account after: still present' } catch { W ('account after: ' + $_.Exception.GetType().FullName) }
'@

function Get-NewtonCleanupScript {
    # The text of the SYSTEM task of stage 9: literal values, then the
    # constant body.  Only DC1's deletes the domain account, last.
    param([bool]$DeleteAccount)
    # The helper, K and the device name are in the helper's install root,
    # where the bootstrap writes them (DESIGN-1.5 open point 23 of task 8);
    # the keys file, pw.bin and a DSRM file are in the build directory.
    $files = @(($script:BuildDir + '\authorized_keys'),
        [string](Join-Path (Get-NewtonInstallRoot) $script:HelperFileName),
        [string](Get-NewtonKeyPath),
        [string](Get-NewtonDevicePath),
        ($script:BuildDir + '\pw.bin'), ($script:BuildDir + '\dsrm.bin'),
        $script:OdjFileDc1, $script:OdjFileDc2)
    # The stage 8 templates and the write helper the bootstrap installed
    # (DC1's only).
    foreach ($one in $script:SetupTemplates.Values) { $files += [string](Join-Path (Get-NewtonInstallRoot) $one) }
    $files += [string](Join-Path (Get-NewtonInstallRoot) $script:WriteHelperFileName)
    $lines = @(
        '# Newton AD build, stage 9: the cleanup, run once as SYSTEM.',
        ('$Delay = ' + [string]$script:CleanupDelaySeconds),
        ('$Log = ' + (ConvertTo-NewtonLiteral $script:CleanupLogPath)),
        ('$SshdConfig = ' + (ConvertTo-NewtonLiteral $script:SshdConfigPath)),
        ('$BlockMarker = ' + (ConvertTo-NewtonLiteral $script:BuildBlockMarker)),
        ('$Files = ' + (ConvertTo-NewtonListLiteral ([string[]]$files))),
        ('$BuildUser = ' + (ConvertTo-NewtonLiteral $script:BuildUser)),
        ('$Task = ' + (ConvertTo-NewtonLiteral $script:CleanupTaskName)),
        ('$Self = ' + (ConvertTo-NewtonLiteral $script:CleanupScriptPath))
    )
    $body = $script:CleanupBody
    if ($DeleteAccount) {
        $tail = "try { Unregister-ScheduledTask"
        $at = $body.IndexOf($tail, [System.StringComparison]::Ordinal)
        $body = $body.Substring(0, $at) + $script:CleanupAccountBody + "`n" + $body.Substring($at)
    }
    return (($lines -join "`n") + "`n" + $body + "`n")
}

# ---------------------------------------------------------------------------
# stage 8: the 1.4 newton-ops setup and the 1.3 newton-audit setup (the maintainer's
# decision R1, 2026-11-15, and his rulings on open points 34 and 37,
# 2026-11-16)
#
# DC1 runs the two setups through the setup generators' own code paths:
# the bootstrap installed each generator's build template in the install
# root (setupgen.windows_template and setupgen_write.windows_write_template,
# build=True), and the helper fills the placeholders the generators fill
# (setupgen.FILL_FIELDS, setupgen_write.WRITE_FILL_FIELDS) from the plan
# bytes, and the write helper's bytes from the file the bootstrap installed
# beside the templates (WriteHelperFileName), which must hash to the plan's
# ops.write_helper_sha256 (the maintainer's decision of 2026-11-19 on the stage 8
# transport: Windows PowerShell 5.1 under OpenSSH hangs reading stdin past
# about 70 to 80 KB, and the write helper is about 182 KB in a request, so
# nothing large goes over stdin).  Each filled setup runs in the
# password task (the 1.4 setup backs the PDC's policy up, which a key login
# cannot do reliably).  Neither restarts sshd: the helper registers one
# SYSTEM task that restarts it once both are in, after this answer has
# left, and a later status reads stage 8 back once that task's result file
# says sshd came back.
# ---------------------------------------------------------------------------

$script:OpsStage = '8'
$script:OpsPhases = @('s8_setup', 's8_restart')
# The write helper the bootstrap installed in the install root (DC1's
# only; bootstrap.WRITE_HELPER_FILE), and the next step of a stage 8 that
# finds it missing or changed.  The helper never asks for the bytes again.
$script:WriteHelperFileName = 's8-write.ps1'
$script:WriteHelperNextStep = 'run the bootstrap of the server again: it installs the write helper of this Newton, then run the build again'
$script:Ed25519KeyPattern = '\Assh-ed25519 [A-Za-z0-9+/]{68}\z'
$script:Sha256Pattern = '\A[0-9a-f]{64}\z'
$script:SetupTemplates = [ordered]@{ 's8-audit' = 's8-audit.tmpl.ps1'; 's8-ops' = 's8-ops.tmpl.ps1' }
$script:SetupScripts = @{ 's8-audit' = 'C:\NewtonBuild\ops\s8-audit-setup.ps1'; 's8-ops' = 'C:\NewtonBuild\ops\s8-ops-setup.ps1' }
$script:OpsAdDir = 'C:\ProgramData\Newton\ad'
$script:SshdRestartOp = 's8-sshd'
$script:SshdRestartTaskName = 'NewtonBuild-sshd-restart'
$script:SshdRestartScriptPath = 'C:\ProgramData\Newton\ad-build-sshd-restart.ps1'
$script:SshdRestartDelaySeconds = 10
$script:SshdRestartWaitSeconds = 900
$script:FingerprintMessage = 'newton-approval-fingerprint-v1'
$script:OpsPrivilegedRids = @('498', '512', '516', '518', '519', '520', '521', '525', '526', '527')
$script:OpsPrivilegedBuiltins = @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551', 'S-1-5-32-552')
# The step lines each filled setup prints, in order (the generators' own
# steps; the build variants have no restart step).
$script:SetupSteps = @{
    's8-audit' = @('Step 1: the newton-audit account', 'Step 2: the collector files', 'Step 3: the access control list',
        'Step 4: the authorized key', 'Step 5: the sshd configuration', 'Step 7: the inventory entry')
    's8-ops' = @('Step 0: the pre-checks', 'Step 1: the newton-ops account', 'Step 2: the delegation',
        'Step 3: the approval key', 'Step 4: the files', 'Step 5: the login', 'Step 6: the SeBatchLogonRight',
        'Step 7: the inventory entry')
}

# The two setups: the op runs the filled setup the helper wrote and prints
# the setup's own lines.
$script:OpBodies['s8-setup'] = @'
'setup script: ' + $SetupScript + ', sha256 ' + (Get-FileHash -Algorithm SHA256 -LiteralPath $SetupScript).Hash.ToLowerInvariant()
$global:LASTEXITCODE = 0
& $SetupScript
'setup exit ' + $LASTEXITCODE
'@

# The sshd restart: a one-shot SYSTEM task, registered from the key login
# and started, as stage 9's cleanup is (measured on both DCs).
$script:OpBodies['s8-restart'] = @'
$dir = Split-Path -Parent $RestartScript
if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir }
[IO.File]::WriteAllText($RestartScript, [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($RestartB64)), (New-Object System.Text.UTF8Encoding $true))
'restart script: ' + $RestartScript + ', bytes ' + (Get-Item -LiteralPath $RestartScript).Length
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + $RestartScript)
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$t = Register-ScheduledTask -TaskName $RestartTask -Action $action -Settings $settings -Principal $principal
'registered ' + $t.TaskName + ' as ' + $t.Principal.UserId + ' LogonType ' + $t.Principal.LogonType
Start-ScheduledTask -TaskName $RestartTask
Start-Sleep -Seconds 2
'state ' + (Get-ScheduledTask -TaskName $RestartTask).State
'@

# The read-back of stage 8, in the password task after sshd came back:
# both logins with the plan's keys, the write helper on disk, K shared,
# sshd answering, newton-audit in no privileged group, and every explicit
# ACE of newton-ops in the domain partition.
$script:OpBodies['s8-read'] = @'
Import-Module ActiveDirectory
$config = [IO.File]::ReadAllText('C:\ProgramData\ssh\sshd_config')
$configLines = @($config -split "`r?`n")
foreach ($user in @('newton-ops', 'newton-audit', 'newton-build')) {
    $pattern = '^\s*Match\s+User\s+(?:\S*,)?' + [regex]::Escape($Netbios.ToLowerInvariant() + '\' + $user) + '(?:,\S*)?\s*$'
    'sshd match ' + $user + ': ' + @($configLines | Where-Object { $_ -match $pattern }).Count
}
'ops keys: ' + ([IO.File]::ReadAllText((Join-Path $AdDir 'write_authorized_keys'))).Trim()
'audit keys: ' + ([IO.File]::ReadAllText((Join-Path $AdDir 'authorized_keys'))).Trim()
'write helper sha256: ' + (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $AdDir 'write.ps1')).Hash.ToLowerInvariant()
'approval key is the build key: ' + (([IO.File]::ReadAllText((Join-Path $AdDir 'approval.key'))).Trim() -ceq ([IO.File]::ReadAllText($BuildKey)).Trim())
'sshd service: ' + (Get-Service -Name sshd).Status
$client = New-Object System.Net.Sockets.TcpClient
try {
    $client.ReceiveTimeout = 10000
    $client.Connect('127.0.0.1', 22)
    $stream = $client.GetStream()
    $buffer = New-Object byte[] 256
    $read = $stream.Read($buffer, 0, $buffer.Length)
    'sshd banner: ' + ([Text.Encoding]::ASCII.GetString($buffer, 0, $read) -split "`r?`n")[0]
} finally { $client.Close() }
$audit = Get-ADUser -Identity 'newton-audit'
$auditGroups = @(Get-ADObject -SearchBase $audit.DistinguishedName -SearchScope Base -Filter '*' -Properties tokenGroups)
'audit token groups: ' + ((@($auditGroups[0].tokenGroups) | ForEach-Object { [string]$_ }) -join ',')
$ops = Get-ADUser -Identity 'newton-ops'
$opsSid = [string]$ops.SID
$scanned = 0
foreach ($object in @(Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -SearchScope Subtree -LDAPFilter '(objectClass=*)' -Properties nTSecurityDescriptor)) {
    $scanned++
    $explicit = @($object.nTSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { (-not $_.IsInherited) -and ([string]$_.IdentityReference -eq $opsSid) }).Count
    if ($explicit -gt 0) { 'ops explicit aces: ' + $object.DistinguishedName + ' | ' + $explicit }
}
'ops ace scan: ' + $scanned + ' objects'
'@

$script:SshdRestartBody = @'
$ErrorActionPreference = 'Continue'
$lines = New-Object System.Collections.ArrayList
$rc = 1
Start-Sleep -Seconds $Delay
[void]$lines.Add('identity ' + (whoami))
try {
    $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    $null = & $sshd -t 2>&1
    $test = $LASTEXITCODE
    [void]$lines.Add('sshd -t exit ' + $test)
    if ($test -eq 0) {
        $before = [string](Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'").ProcessId
        Restart-Service -Name sshd -Force -ErrorAction Stop
        $after = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'"
        [void]$lines.Add('sshd restarted: ' + [string]$after.State + ' | pid ' + $before + ' -> ' + [string]$after.ProcessId)
        if (([string]$after.State -eq 'Running') -and ([string]$after.ProcessId -ne $before)) { $rc = 0 } else { $rc = 3 }
    } else {
        $rc = 2
    }
} catch {
    [void]$lines.Add('FAIL: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message)
    $rc = 1
}
[IO.File]::WriteAllText($OutFile, ((@($lines) -join "`r`n") + "`r`n"))
$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$rc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }
try { Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction Stop } catch { }
try { Remove-Item -LiteralPath $Self -Force -ErrorAction Stop } catch { }
'@

function Get-NewtonSshdRestartScript {
    # The text of the SYSTEM task of stage 8: literal values, then the
    # constant body.  It writes its own output and result file, as an op
    # does, so a status reads the restart from them.
    $lines = @(
        '# Newton AD build, stage 8: the sshd restart, run once as SYSTEM.',
        ('$Delay = ' + [string]$script:SshdRestartDelaySeconds),
        ('$OutFile = ' + (ConvertTo-NewtonLiteral (Get-NewtonOutPath $script:SshdRestartOp))),
        ('$ResultFile = ' + (ConvertTo-NewtonLiteral (Get-NewtonResultPath $script:SshdRestartOp))),
        ('$Task = ' + (ConvertTo-NewtonLiteral $script:SshdRestartTaskName)),
        ('$Self = ' + (ConvertTo-NewtonLiteral $script:SshdRestartScriptPath))
    )
    return (($lines -join "`n") + "`n" + $script:SshdRestartBody + "`n")
}

function Get-NewtonB64Literal {
    # setupgen._b64_literal: a PowerShell array of single-quoted lines of
    # 120 base64 characters, joined back into one string.
    param([string]$Name, [byte[]]$Bytes)
    $encoded = [Convert]::ToBase64String($Bytes)
    $parts = New-Object System.Collections.ArrayList
    for ($index = 0; $index -lt $encoded.Length; $index += 120) {
        [void]$parts.Add("'" + $encoded.Substring($index, [Math]::Min(120, $encoded.Length - $index)) + "'")
    }
    return ('$' + $Name + " = @(`n" + ($parts.ToArray() -join "`n") + "`n)`n$" + $Name + ' = $' + $Name + " -join ''")
}

function Get-NewtonSetupFill {
    # A template of the generators with its placeholders filled, in the
    # order of the generators' lists.  The values were checked against
    # their grammars: none holds '@@', so the order does not matter.
    param([string]$Template, $Fields)
    $text = $Template
    foreach ($pair in $Fields.GetEnumerator()) {
        $text = $text.Replace([string]$pair.Key, [string]$pair.Value)
    }
    if ($text -cmatch '@@[A-Z_]+@@') {
        Throw-NewtonRefusal 'schema' 'a stage 8 template holds a placeholder the plan does not fill'
    }
    return $text
}

function Get-NewtonApprovalFingerprint {
    # approve.approval_fingerprint: HMAC-SHA256 of the fixed message, keyed
    # with K, hex.
    param([byte[]]$Key)
    $mac = Get-NewtonHmac -Key $Key -Data ([Text.Encoding]::ASCII.GetBytes($script:FingerprintMessage))
    return (-join ($mac | ForEach-Object { $_.ToString('x2') }))
}

function Get-NewtonOpsValues {
    # The values of stage 8, out of the plan bytes, each against its
    # grammar: the domain, DC1's device and address, the plan's top-level
    # OUs (the OUs newton-ops is delegated; DESIGN-1.5 open point 37), the
    # two public keys and the write helper's sha256.
    param([hashtable]$Plan, [string]$Role)
    if ($Role -cne 'dc1') { Throw-NewtonRefusal 'schema' 'stage 8 runs on DC1 only' }
    $values = Get-NewtonStageValues -Plan $Plan -Role $Role
    $index = Get-NewtonPlanServerIndex -Plan $Plan -Role $Role
    $device = Get-NewtonPlanValue -Plan $Plan -Key ('servers.' + [string]$index + '.device') -Pattern $script:DevicePattern
    $opsKey = Get-NewtonPlanValue -Plan $Plan -Key 'ops.public_key' -Pattern $script:Ed25519KeyPattern
    $auditKey = Get-NewtonPlanValue -Plan $Plan -Key 'ops.audit_public_key' -Pattern $script:Ed25519KeyPattern
    if ($opsKey -ceq $auditKey) { Throw-NewtonRefusal 'schema' 'the newton-audit key of the plan is the newton-ops key' }
    $sha = Get-NewtonPlanValue -Plan $Plan -Key 'ops.write_helper_sha256' -Pattern $script:Sha256Pattern
    $domainDn = (@(([string]$values['DnsName']).Split('.') | ForEach-Object { 'DC=' + $_ }) -join ',')
    $tops = New-Object System.Collections.ArrayList
    foreach ($path in @($values['OuTree'])) {
        $top = ([string]$path).Split('/')[0]
        $seen = $false
        foreach ($one in $tops) { if ($one -ieq $top) { $seen = $true } }
        if (-not $seen) { [void]$tops.Add($top) }
    }
    if ($tops.Count -eq 0) { Throw-NewtonRefusal 'schema' 'the plan holds no OU to delegate to newton-ops' }
    $values['Device'] = $device
    $values['OpsKey'] = $opsKey
    $values['AuditKey'] = $auditKey
    $values['WriteHelperSha'] = $sha
    $values['DomainDn'] = $domainDn
    $values['OpsOus'] = [string[]]@($tops | ForEach-Object { 'OU=' + $_ + ',' + $domainDn })
    $values['AdDir'] = $script:OpsAdDir
    $values['BuildKey'] = [string](Get-NewtonKeyPath)
    return $values
}

function Get-NewtonSetupText {
    # One filled setup of stage 8: the generator's build template from the
    # install root with the plan's values (and, for the write setup, the
    # installed write helper).
    param([string]$Op, $Values, [byte[]]$Helper)
    $path = Join-Path (Get-NewtonInstallRoot) ([string]$script:SetupTemplates[$Op])
    if (-not (Test-Path -LiteralPath $path)) {
        Throw-NewtonRefusal 'schema' ('the bootstrap installed no stage 8 template ' + [string]$script:SetupTemplates[$Op])
    }
    $template = [System.IO.File]::ReadAllText($path)
    $domain = [string]$Values['DnsName']
    $hostValue = [string]$Values['Ip']
    $device = [string]$Values['Device']
    if ($Op -ceq 's8-audit') {
        $key = [string]$Values['AuditKey']
        $fields = [ordered]@{
            '@@DOMAIN@@' = $domain
            '@@DEVICE@@' = $device
            '@@HOST@@' = $hostValue
            '@@KEYLINE@@' = $key
            '@@KEYSHA@@' = (Get-NewtonSha256Hex ([Text.Encoding]::UTF8.GetBytes($key)))
        }
        return (Get-NewtonSetupFill -Template $template -Fields $fields)
    }
    $key = [string]$Values['OpsKey']
    $ous = (@($Values['OpsOus'] | ForEach-Object { "    '" + $_ + "'" }) -join "`n")
    $fields = [ordered]@{
        '@@DOMAIN@@' = $domain
        '@@DEVICE@@' = $device
        '@@DOMAIN_DEVICE@@' = $device
        '@@HOST@@' = $hostValue
        '@@DOMAIN_DN@@' = [string]$Values['DomainDn']
        '@@OUS@@' = $ous
        '@@HELPER@@' = (Get-NewtonB64Literal -Name 'helperB64' -Bytes $Helper)
        '@@HELPER_HASH@@' = (Get-NewtonSha256Hex $Helper)
        '@@KEYLINE@@' = $key
        '@@KEYSHA@@' = (Get-NewtonSha256Hex ([Text.Encoding]::UTF8.GetBytes($key)))
    }
    return (Get-NewtonSetupFill -Template $template -Fields $fields)
}

function Write-NewtonSetupScript {
    # A filled setup, where its op runs it.
    param([string]$Path, [string]$Text)
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Path $directory -Force }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding $true))
}

function Get-NewtonOutPath {
    # The output file of one op.
    param([string]$Op)
    return $script:BuildDir + '\out\' + $Op + '.txt'
}

function Get-NewtonResultPath {
    # The result file of one op: its exit code, written by the op itself
    # after its output file is closed, so a status request can record
    # the outcome of an op whose helper session dropped (DESIGN-1.5, "The
    # build account after promotion").
    param([string]$Op)
    return $script:BuildDir + '\out\' + $Op + '.rc'
}

function Get-NewtonOpPath {
    # The script file of one op.
    param([string]$Op)
    return $script:BuildDir + '\ops\' + $Op + '.ps1'
}

function Get-NewtonOpScript {
    # The script of one op: the header assigns every value as a
    # single-quoted literal, then the wrapper of the measurement runs the
    # constant body and writes everything it prints to the out file.
    param([string]$Op, $Values)
    if (-not $script:OpStage.Contains($Op)) {
        Throw-NewtonRefusal 'schema' 'the op is not one of the ops of the helper'
    }
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add('# Newton AD build, stage ' + $script:OpStage[$Op] + ', op ' + $Op + '.')
    [void]$lines.Add('# Rendered by the build helper from the approved plan; the values are the ones of the plan.')
    [void]$lines.Add('$OutFile = ' + (ConvertTo-NewtonLiteral (Get-NewtonOutPath $Op)))
    [void]$lines.Add('$ResultFile = ' + (ConvertTo-NewtonLiteral (Get-NewtonResultPath $Op)))
    foreach ($one in $script:OpValues[$Op]) {
        # 'Variable=Value': the header variable of the body and the value
        # it holds; a bare name is both.
        $variable = $one
        $name = $one
        if ($one.Contains('=')) { $variable, $name = $one.Split('=', 2) }
        if (-not $Values.Contains($name)) {
            Throw-NewtonRefusal 'schema' ('the op has no value ' + $name)
        }
        if ($script:ListValues -ccontains $name) {
            [void]$lines.Add('$' + $variable + ' = ' + (ConvertTo-NewtonListLiteral ([string[]]@($Values[$name]))))
        } else {
            [void]$lines.Add('$' + $variable + ' = ' + (ConvertTo-NewtonLiteral ([string]$Values[$name])))
        }
    }
    [void]$lines.Add('$global:NewtonRc = 0')
    [void]$lines.Add('& {')
    [void]$lines.Add('try {')
    [void]$lines.Add('$ErrorActionPreference = ''Stop''')
    [void]$lines.Add('$ProgressPreference = ''SilentlyContinue''')
    [void]$lines.Add('''task identity: '' + (whoami) + '' | auth '' + [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType')
    [void]$lines.Add('''task start '' + (Get-Date).ToUniversalTime().ToString(''o'')')
    $body = $Op
    if ($script:OpBodyOf.ContainsKey($Op)) { $body = [string]$script:OpBodyOf[$Op] }
    foreach ($line in ($script:OpBodies[$body] -split "`r?`n")) { [void]$lines.Add($line) }
    [void]$lines.Add('} catch {')
    [void]$lines.Add('''FAIL: '' + $_.Exception.GetType().FullName + '': '' + $_.Exception.Message')
    [void]$lines.Add('$global:NewtonRc = 1')
    [void]$lines.Add('}')
    [void]$lines.Add('''task end '' + (Get-Date).ToUniversalTime().ToString(''o'')')
    [void]$lines.Add('} *>&1 | Out-File -FilePath $OutFile -Encoding utf8 -Width 4096')
    [void]$lines.Add('$resultStream = [System.IO.File]::Open($ResultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)')
    [void]$lines.Add('try { $resultBytes = [System.Text.Encoding]::ASCII.GetBytes([string]$global:NewtonRc); $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) } finally { $resultStream.Close() }')
    [void]$lines.Add('exit $global:NewtonRc')
    return (($lines.ToArray() -join "`n") + "`n")
}

# ---------------------------------------------------------------------------
# the parsers: the output of an op, read back into checks
# ---------------------------------------------------------------------------

function Get-NewtonOutputLines {
    # The lines of the output of an op: Out-File writes a BOM and CRLF.
    param([string]$Output)
    if ($null -eq $Output) { return ,@() }
    $text = $Output
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    return ,@($text -split "`r?`n")
}

function New-NewtonVerdict {
    return @{ checks = (New-Object System.Collections.ArrayList); code = '' }
}

function Add-NewtonCheck {
    # One check of a verdict.  The first check that fails names the code
    # of the stop.
    param([hashtable]$Verdict, [string]$Name, [bool]$Ok, [string]$Detail, [string]$Code)
    if ($null -eq $Detail) { $Detail = '' }
    if ($Detail.Length -gt 200) { $Detail = $Detail.Substring(0, 200) }
    [void]$Verdict['checks'].Add([ordered]@{ name = $Name; ok = $Ok; detail = $Detail })
    if ((-not $Ok) -and ([string]::IsNullOrEmpty([string]$Verdict['code']))) {
        $Verdict['code'] = $Code
    }
}

function Find-NewtonLine {
    # The first line that starts with a prefix (ordinal), or $null.
    param($Lines, [string]$Prefix)
    foreach ($line in $Lines) {
        if ($line.StartsWith($Prefix, [System.StringComparison]::Ordinal)) { return $line }
    }
    return $null
}

function Find-NewtonLines {
    param($Lines, [string]$Prefix)
    $found = New-Object System.Collections.ArrayList
    foreach ($line in $Lines) {
        if ($line.StartsWith($Prefix, [System.StringComparison]::Ordinal)) { [void]$found.Add($line) }
    }
    return ,$found.ToArray()
}

function Get-NewtonAfterPrefix {
    param([string]$Line, [string]$Prefix)
    # A [string] parameter turns $null into '': a line that was not
    # found is $null here, never a Substring error.
    if ([string]::IsNullOrEmpty($Line)) { return $null }
    return $Line.Substring($Prefix.Length)
}

function Test-NewtonOpFailed {
    # An op that exited non-zero or printed the FAIL line of its wrapper.
    param([int]$Result, $Lines)
    if ($Result -ne 0) { return $true }
    return ($null -ne (Find-NewtonLine $Lines 'FAIL: '))
}

function Get-NewtonDomainDn {
    param([string]$DnsName)
    return 'DC=' + ($DnsName.Split('.') -join ',DC=')
}

function Get-NewtonStage0Verdict {
    # Stage 0 (DESIGN-1.5, the stage table): Server 2025, workgroup, no
    # AD DS, the IP, prefix and gateway already the plan's, the clock
    # within 5 minutes of the NBF, 20 GB free, the plan's DNS name free,
    # and on Proxmox the agent and the VirtIO serial device.
    param($Lines, $Values, [int64]$Now, [int64]$NotBefore)
    $verdict = New-NewtonVerdict

    $os = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'os: ') 'os: '
    $osOk = ($null -ne $os) -and $os.StartsWith('Microsoft Windows Server 2025 ', [System.StringComparison]::Ordinal) -and
        ($os.Contains(' | BuildNumber 26100 |'))
    Add-NewtonCheck $verdict 'os' $osOk ([string]$os) 'os_mismatch'

    $cs = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'cs: ') 'cs: '
    $csOk = ($null -ne $cs) -and $cs.Contains(' | DomainRole 2 | PartOfDomain False | ')
    Add-NewtonCheck $verdict 'workgroup' $csOk ([string]$cs) 'not_workgroup'

    $features = Find-NewtonLine $Lines 'AD-Domain-Services '
    $addsOk = ($null -ne $features) -and $features.StartsWith('AD-Domain-Services Available |', [System.StringComparison]::Ordinal)
    Add-NewtonCheck $verdict 'adds' $addsOk ([string]$features) 'adds_present'

    $address = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'Get-NetIPAddress: ') 'Get-NetIPAddress: '
    $ipOk = $false
    $ipDetail = [string]$address
    if (($null -ne $address) -and ($address -cmatch '\A(.+) (\S+) /([0-9]+) PrefixOrigin (\S+)\z')) {
        $alias = $Matches[1]
        $ipOk = ($Matches[2] -ceq [string]$Values['Ip']) -and ($Matches[3] -ceq [string]$Values['Prefix']) -and
            ($Matches[4] -ceq 'Manual')
        $routes = Find-NewtonLines $Lines 'Get-NetRoute 0.0.0.0/0: '
        $hops = New-Object System.Collections.ArrayList
        foreach ($route in $routes) {
            if ($route -cmatch '\AGet-NetRoute 0\.0\.0\.0/0: (.+) NextHop (\S+) RouteMetric [0-9]+\z') {
                [void]$hops.Add(@{ alias = $Matches[1]; hop = $Matches[2] })
            } else {
                [void]$hops.Add(@{ alias = ''; hop = '' })
            }
        }
        $routeOk = ($hops.Count -eq 1) -and ([string]$hops[0]['alias'] -ceq $alias) -and
            ([string]$hops[0]['hop'] -ceq [string]$Values['Gateway'])
        $ipOk = $ipOk -and $routeOk
        $ipDetail = $address + ' | ' + ($routes -join ' | ')
    }
    Add-NewtonCheck $verdict 'ip' $ipOk $ipDetail 'ip_mismatch'

    $skew = [Math]::Abs($Now - $NotBefore)
    Add-NewtonCheck $verdict 'clock' ($skew -le $script:ClockSkewSeconds) ('seconds from the NBF: ' + [string]$skew) 'clock_skew'

    $disk = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'C: free bytes ') 'C: free bytes '
    $diskOk = $false
    if (($null -ne $disk) -and ($disk -cmatch '\A([0-9]+) ')) {
        $diskOk = ([int64]$Matches[1] -ge $script:MinFreeBytes)
    }
    Add-NewtonCheck $verdict 'disk' $diskOk ('C: free bytes ' + [string]$disk) 'disk_low'

    # The DNS name: an answer means the name is taken; only 9003
    # (DNS_ERROR_RCODE_NAME_ERROR) means it is free.  1460 (no server, or
    # no answer) and 9002 (the server failed to forward) mean the check
    # could not be made (MEASURED-1.5, stage 0).
    $prefix = 'Resolve-DnsName ' + [string]$Values['DnsName'] + ' -DnsOnly True '
    $dns = Get-NewtonAfterPrefix (Find-NewtonLine $Lines $prefix) $prefix
    $dnsOk = $false
    $dnsCode = 'dns_unchecked'
    if (($null -ne $dns) -and ($dns -cmatch '\AOK in [0-9]+ ms: ')) {
        $dnsCode = 'domain_exists'
    } elseif (($null -ne $dns) -and ($dns -cmatch '\AFAIL in [0-9]+ ms: [^|]* \| NativeErrorCode ([0-9]+) \| ')) {
        if ($Matches[1] -ceq '9003') { $dnsOk = $true }
    }
    Add-NewtonCheck $verdict 'domain' $dnsOk ([string]$dns) $dnsCode

    if ([string]$Values['Checkpoint'] -ceq 'proxmox') {
        $agent = Find-NewtonLine $Lines 'QEMU-GA: '
        $serial = Find-NewtonLines $Lines 'VirtIO Serial Driver: '
        $agentOk = ($agent -ceq 'QEMU-GA: Running, Automatic') -and ($serial.Count -ge 1)
        foreach ($one in $serial) {
            if (-not $one.StartsWith('VirtIO Serial Driver: OK, ', [System.StringComparison]::Ordinal)) { $agentOk = $false }
        }
        Add-NewtonCheck $verdict 'agent' $agentOk ([string]$agent + ' | ' + ($serial -join ' | ')) 'agent_missing'
    } else {
        Add-NewtonCheck $verdict 'agent' $true 'not a Proxmox guest' 'agent_missing'
    }
    return $verdict
}

function Get-NewtonIpLine {
    param($Values)
    return 'ip: ' + [string]$Values['Ip'] + '/' + [string]$Values['Prefix'] + ' Manual gw ' + [string]$Values['Gateway']
}

function Get-NewtonStage1BaseVerdict {
    # Stage 1, the run: the IP before and after is the plan's (the stage
    # never touches it), the time source configured, the features
    # installed.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $expected = Get-NewtonIpLine $Values
    $before = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'before ip: ') 'before '
    $after = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'after ip: ') 'after '
    Add-NewtonCheck $verdict 'ip' (($before -ceq $expected) -and ($after -ceq $expected)) `
        ('before ' + [string]$before + ' | after ' + [string]$after) 'ip_mismatch'
    $w32 = Find-NewtonLine $Lines 'w32tm /config exit '
    Add-NewtonCheck $verdict 'time' ($w32 -ceq 'w32tm /config exit 0') ([string]$w32) 'op_failed'
    $install = Find-NewtonLine $Lines 'Install-WindowsFeature in '
    $installOk = ($null -ne $install) -and ($install -cmatch ' ms: Success True RestartNeeded \S+ ExitCode Success\z')
    Add-NewtonCheck $verdict 'features' $installOk ([string]$install) 'op_failed'
    return $verdict
}

function Get-NewtonFeatureState {
    # The InstallState of a feature in the Format-Table of Get-WindowsFeature.
    param($Lines, [string]$Name)
    foreach ($line in $Lines) {
        if ($line -cmatch ('\A' + [regex]::Escape($Name) + ' +(\S+)\s*\z')) { return $Matches[1] }
    }
    return ''
}

function Get-NewtonStage1ReadVerdict {
    # Stage 1, after the reboot: the name, the features, the IP, the DNS
    # client and the time configuration (the source stays Local CMOS
    # Clock while nothing answers NTP, so the configuration is read).
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $cs = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'cs: ') 'cs: '
    $nameOk = ($null -ne $cs) -and $cs.StartsWith('Name ' + [string]$Values['HostName'] + ' | ', [System.StringComparison]::OrdinalIgnoreCase) -and
        $cs.Contains(' | PartOfDomain False | ')
    Add-NewtonCheck $verdict 'name' $nameOk ([string]$cs) 'readback_failed'
    $missing = New-Object System.Collections.ArrayList
    foreach ($feature in @('AD-Domain-Services', 'RSAT-AD-Tools', 'RSAT-AD-PowerShell', 'Windows-Server-Backup')) {
        if ((Get-NewtonFeatureState $Lines $feature) -cne 'Installed') { [void]$missing.Add($feature) }
    }
    Add-NewtonCheck $verdict 'features' ($missing.Count -eq 0) ('not installed: ' + ($missing.ToArray() -join ', ')) 'readback_failed'
    $ip = Find-NewtonLine $Lines 'ip: '
    Add-NewtonCheck $verdict 'ip' ($ip -ceq (Get-NewtonIpLine $Values)) ([string]$ip) 'ip_mismatch'
    $client = Find-NewtonLine $Lines 'dns client: '
    $clientOk = ($client -ceq ('dns client: ' + ([string[]]@($Values['Forwarders']) -join ',')))
    Add-NewtonCheck $verdict 'dns_client' $clientOk ([string]$client) 'readback_failed'
    $type = Find-NewtonLine $Lines 'Type: '
    $peer = Find-NewtonLine $Lines 'NtpServer: '
    $timeOk = ($type -ceq 'Type: NTP (Local)') -and ($peer -ceq ('NtpServer: ' + [string]$Values['TimePeer'] + ',0x8 (Local)'))
    Add-NewtonCheck $verdict 'time' $timeOk ([string]$type + ' | ' + [string]$peer) 'readback_failed'
    return $verdict
}

function Get-NewtonRoleVerdict {
    # The role of the server before stage 2 promotes it.  Measured on
    # BUILD1 (MEASURED-1.5, "Stage 2 resumed: the role of the server"):
    #   after stage 1:  DomainRole 2, PartOfDomain False, Domain WORKGROUP,
    #     ProductType ServerNT, NTDS Parameters absent.
    #   after Install-ADDSForest, before any reboot: DomainRole 3 (the
    #     member-server value), PartOfDomain True, Domain <the plan's>,
    #     ProductType LanmanNT, NTDS Parameters present with the Root
    #     Domain of the new forest, Get-ADDomain failing.
    #   after the first boot: DomainRole 5, the same, Get-ADDomain
    #     answering with the DNS root and the NetBIOS name.
    # The verdict holds promoted: $true for this plan's forest root
    # (promoted, rebooted or not), and the promotion is skipped; $false
    # for the measured workgroup server, and the promotion runs.  Any
    # other role stops the stage: a DC, or a server promoted, in another
    # domain is domain_mismatch; anything else (a member server, a
    # workgroup server with NTDS parameters) is not_workgroup.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $verdict['promoted'] = $false
    $csLine = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'cs: ') 'cs: '
    $product = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'ProductType: ') 'ProductType: '
    $ntds = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'NTDS Parameters: ') 'NTDS Parameters: '
    $ad = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'Get-ADDomain: ') 'Get-ADDomain: '
    $csPattern = '\AName \S+ \| DomainRole ([0-9]) \| PartOfDomain (True|False) \| Domain (\S+) \| Workgroup ?(\S*)\s*\z'
    if (($null -eq $csLine) -or ($null -eq $product) -or ($null -eq $ntds) -or ($null -eq $ad) -or
        ($csLine -cnotmatch $csPattern)) {
        Add-NewtonCheck $verdict 'role' $false 'the role read is incomplete' 'readback_failed'
        return $verdict
    }
    $domainRole = $Matches[1]
    $partOfDomain = $Matches[2]
    $domain = $Matches[3]
    $dnsName = [string]$Values['DnsName']
    $netbios = [string]$Values['Netbios']
    $detail = 'DomainRole ' + $domainRole + ' | Domain ' + $domain + ' | ProductType ' + $product

    if (($domainRole -eq '2') -and ($partOfDomain -ceq 'False') -and ($product -ceq 'ServerNT') -and
        ($ntds -ceq 'absent')) {
        Add-NewtonCheck $verdict 'role' $true ('a workgroup server: the promotion runs | ' + $detail) ''
        return $verdict
    }

    $rootDomain = ''
    if ($ntds -cmatch '\Apresent \| Root Domain (\S+) \| ') { $rootDomain = $Matches[1] }
    $looksDc = ($product -ceq 'LanmanNT') -or ($ntds -cne 'absent')
    if (-not $looksDc) {
        Add-NewtonCheck $verdict 'role' $false ('not the workgroup server stage 2 promotes | ' + $detail) 'not_workgroup'
        return $verdict
    }
    $adOk = $true
    if ($ad -cmatch '\ADNSRoot (\S+) \| NetBIOSName (\S+)\z') {
        $adOk = ($Matches[1] -ieq $dnsName) -and ($Matches[2] -ieq $netbios)
    } elseif (-not $ad.StartsWith('FAIL ', [System.StringComparison]::Ordinal)) {
        $adOk = $false
    }
    $ours = ($product -ceq 'LanmanNT') -and (@('3', '5') -contains $domainRole) -and
        ($partOfDomain -ceq 'True') -and ($domain -ieq $dnsName) -and
        ($rootDomain -ieq (Get-NewtonDomainDn $dnsName)) -and $adOk
    if (-not $ours) {
        if (($product -ceq 'LanmanNT') -and ($rootDomain -ne '')) {
            Add-NewtonCheck $verdict 'role' $false ('a domain controller of another domain | ' + $detail) 'domain_mismatch'
        } else {
            Add-NewtonCheck $verdict 'role' $false ('not the workgroup server stage 2 promotes | ' + $detail) 'not_workgroup'
        }
        return $verdict
    }
    $verdict['promoted'] = $true
    Add-NewtonCheck $verdict 'role' $true ('already the forest root of ' + $dnsName + ': the promotion is skipped | ' + $detail) ''
    return $verdict
}

function Get-NewtonPromoteVerdict {
    # Stage 2, the promotion: the DSRM file gone, Status Success and
    # RebootRequired True (MEASURED-1.5: -NoRebootOnCompletion).
    param($Lines)
    $verdict = New-NewtonVerdict
    $deleted = Find-NewtonLine $Lines 'dsrm.bin deleted: '
    Add-NewtonCheck $verdict 'dsrm_file' ($deleted -ceq 'dsrm.bin deleted: True') ([string]$deleted) 'op_failed'
    $status = Find-NewtonLine $Lines 'Status '
    $reboot = Find-NewtonLine $Lines 'RebootRequired '
    $ok = ($status -cmatch '\AStatus +: Success\s*\z') -and ($reboot -cmatch '\ARebootRequired +: True\s*\z')
    Add-NewtonCheck $verdict 'promotion' $ok ([string]$status + ' | ' + [string]$reboot) 'op_failed'
    return $verdict
}

function Get-NewtonGroupsVerdict {
    # Stage 2 after the first boot: the build account in the three groups.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $user = [string]$Values['BuildUser']
    $ok = $true
    foreach ($group in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
        if ($null -eq (Find-NewtonLine $Lines ('Add-ADGroupMember ''' + $group + ''' ' + $user + ': ok'))) { $ok = $false }
    }
    $line = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'Get-ADPrincipalGroupMembership: ') 'Get-ADPrincipalGroupMembership: '
    $names = @()
    if ($null -ne $line) { $names = @($line.Split(',') | ForEach-Object { $_.Trim() }) }
    foreach ($group in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
        if ($names -cnotcontains $group) { $ok = $false }
    }
    Add-NewtonCheck $verdict 'memberships' $ok ([string]$line) 'op_failed'
    return $verdict
}

function Test-NewtonGenerationId {
    # msDS-GenerationId on the DC's computer object: present, 8 bytes.
    param($Lines)
    foreach ($line in $Lines) {
        if ($line -cmatch '\AmsDS-GenerationId on .+: present, 8 bytes, [0-9a-f]{16}\z') { return $true }
    }
    return $false
}

function Get-NewtonDcdiagCheck {
    # The test lines of dcdiag: every test of the list passed and none
    # failed but the two a fresh forest fails on its own first boots.
    # dcdiag exits 0 with failed tests, so the lines are the read-back.
    param($Lines)
    $passed = @{}
    $failed = New-Object System.Collections.ArrayList
    foreach ($line in $Lines) {
        if ($line -cmatch '\A\s*\.{5,} (\S+) (passed|failed) test ?(\S*)\s*\z') {
            $test = $Matches[3]
            if ($Matches[2] -ceq 'passed') {
                if (-not [string]::IsNullOrEmpty($test)) { $passed[$test] = $true }
            } else {
                if ($script:DcdiagAcceptedFailures -cnotcontains $test) { [void]$failed.Add($Matches[1] + ' ' + $test) }
            }
        }
    }
    $missing = New-Object System.Collections.ArrayList
    foreach ($test in $script:DcdiagMustPass) {
        if (-not $passed.ContainsKey($test)) { [void]$missing.Add($test) }
    }
    $ok = ($failed.Count -eq 0) -and ($missing.Count -eq 0)
    $detail = 'failed: ' + ($failed.ToArray() -join ', ') + ' | not passed: ' + ($missing.ToArray() -join ', ')
    return @{ ok = $ok; detail = $detail }
}

function Get-NewtonDcdiagServerCheck {
    # The test lines of a full dcdiag against one server (stage 7's
    # read-back): every server test of the list passed by that server,
    # every partition and enterprise test of the list passed, and no test
    # failed but the accepted pair (a failed test without a name is a
    # failure).  dcdiag /q prints no line for a test that passed, so it
    # cannot show that a test ran (X3 of a review); the caller
    # also requires exit 0.
    # With -AcceptOldReplications, the Replications test may fail as well:
    # the caller proved that the old-row rule of 2026-11-23 accepted the
    # failing rows of repadmin.  The failure must name the server, and the
    # test must have run (a test that never ran is missing, not failed).
    param($Lines, [string]$Server, [switch]$AcceptOldReplications)
    $passed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $failed = New-Object System.Collections.ArrayList
    $oldReplications = $false
    foreach ($line in $Lines) {
        if ([string]$line -cmatch '\A\s*\.{5,} (\S+) (passed|failed) test ?(\S*)\s*\z') {
            $subject = $Matches[1]
            $test = $Matches[3]
            if ($Matches[2] -ceq 'failed') {
                if (($test -ceq 'Replications') -and $AcceptOldReplications -and
                    $subject.Equals($Server, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $oldReplications = $true
                    continue
                }
                if ($script:DcdiagAcceptedFailures -cnotcontains $test) { [void]$failed.Add($subject + ' ' + $test) }
            } elseif (-not [string]::IsNullOrEmpty($test)) {
                if ($subject.Equals($Server, [System.StringComparison]::OrdinalIgnoreCase)) { [void]$passed.Add('server ' + $test) }
                [void]$passed.Add('any ' + $test)
            }
        }
    }
    $missing = New-Object System.Collections.ArrayList
    foreach ($test in $script:DcdiagMustPass) {
        $key = 'server ' + $test
        if ($script:DcdiagEnterpriseTests -ccontains $test) { $key = 'any ' + $test }
        if (-not $passed.Contains($key)) {
            if (($test -ceq 'Replications') -and $oldReplications) { continue }
            [void]$missing.Add($test)
        }
    }
    $ok = ($failed.Count -eq 0) -and ($missing.Count -eq 0)
    $detail = 'failed: ' + ($failed.ToArray() -join ', ') + ' | not passed by ' + $Server + ': ' + ($missing.ToArray() -join ', ')
    return @{ ok = $ok; detail = $detail }
}

function Test-NewtonTokenGroups {
    # The groups of the build login's own S4U token, from whoami /groups
    # /fo csv /nh: the three groups of stage 2 by their RID.
    param($Groups)
    $found = @{}
    foreach ($line in $Groups) {
        if ([string]$line -cmatch '\A"[^"]*","Group","S-1-5-21-[0-9]+-[0-9]+-[0-9]+-([0-9]+)","[^"]*Enabled group[^"]*"\z') {
            $found[$Matches[1]] = $true
        }
    }
    foreach ($rid in $script:BuildGroupRids) {
        if (-not $found.ContainsKey($rid)) { return $false }
    }
    return $true
}

function Get-NewtonStage2ReadVerdict {
    # Stage 2's read-back (DESIGN-1.5, the stage table): dcdiag, SYSVOL
    # and NETLOGON, the SRV records, the levels, the forwarders, the
    # memberships in the directory and in an S4U token.
    param($Lines, $Values, $Groups)
    $verdict = New-NewtonVerdict
    $dns = [string]$Values['DnsName']
    $dcdiag = Get-NewtonDcdiagCheck $Lines
    Add-NewtonCheck $verdict 'dcdiag' ([bool]$dcdiag['ok']) ([string]$dcdiag['detail']) 'readback_failed'

    $ready = Find-NewtonLine $Lines 'SYSVOLReady: '
    $sysvolShare = $null -ne (Find-NewtonLine $Lines 'SYSVOL ')
    Add-NewtonCheck $verdict 'sysvol' (($ready -ceq 'SYSVOLReady: 1') -and $sysvolShare) ([string]$ready) 'readback_failed'
    $netlogon = Find-NewtonLine $Lines 'NETLOGON '
    Add-NewtonCheck $verdict 'netlogon' ($null -ne $netlogon) ([string]$netlogon) 'readback_failed'

    $target = ([string]$Values['HostName'] + '.' + $dns).ToLowerInvariant()
    $srvOk = $true
    foreach ($pair in @(@('_ldap._tcp.dc._msdcs.', '389'), @('_kerberos._tcp.', '88'), @('_gc._tcp.', '3268'), @('_ldap._tcp.pdc._msdcs.', '389'))) {
        $want = ('SRV ' + $pair[0] + $dns + ' -> ' + $target + ':' + $pair[1]).ToLowerInvariant()
        $seen = $false
        foreach ($line in (Find-NewtonLines $Lines 'SRV ')) {
            if ($line.ToLowerInvariant() -ceq $want) { $seen = $true }
        }
        if (-not $seen) { $srvOk = $false }
    }
    Add-NewtonCheck $verdict 'srv' $srvOk ((Find-NewtonLines $Lines 'SRV ') -join ' | ') 'readback_failed'

    $names = $script:LevelNames[[string]$Values['Level']]
    $mode = Find-NewtonLine $Lines 'ForestMode '
    $wantMode = 'ForestMode ' + $names['forest'] + ' DomainMode ' + $names['domain'] + ' | forest ' + $dns + ' | NetBIOS ' + [string]$Values['Netbios'] + ' | '
    $version = Find-NewtonLine $Lines 'msDS-Behavior-Version: '
    $wantVersion = 'msDS-Behavior-Version: forest ' + $names['version'] + ' domain ' + $names['version']
    $levelsOk = ($null -ne $mode) -and $mode.StartsWith($wantMode, [System.StringComparison]::Ordinal) -and ($version -ceq $wantVersion)
    Add-NewtonCheck $verdict 'levels' $levelsOk ([string]$version) 'readback_failed'

    $forwarders = Find-NewtonLine $Lines 'DNS forwarders: '
    $wantForwarders = 'DNS forwarders: ' + ([string[]]@($Values['Forwarders']) -join ',')
    Add-NewtonCheck $verdict 'forwarders' ($forwarders -ceq $wantForwarders) ([string]$forwarders) 'readback_failed'

    $prefix = [string]$Values['BuildUser'] + ' memberships (Get-ADPrincipalGroupMembership): '
    $line = Get-NewtonAfterPrefix (Find-NewtonLine $Lines $prefix) $prefix
    $memberOk = $null -ne $line
    $list = @()
    if ($memberOk) { $list = @($line.Split(',') | ForEach-Object { $_.Trim() }) }
    foreach ($group in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
        if ($list -cnotcontains $group) { $memberOk = $false }
    }
    Add-NewtonCheck $verdict 'memberships' $memberOk ([string]$line) 'readback_failed'

    Add-NewtonCheck $verdict 's4u_token' (Test-NewtonTokenGroups $Groups) 'the groups 512, 518 and 519 in the S4U token of the build login' 'readback_failed'
    return $verdict
}

function Get-NewtonStage3Verdict {
    # Stage 3: not enabled before (the state the stage was approved on),
    # and afterwards its scope is the Partitions container.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $before = Find-NewtonLine $Lines 'before: EnabledScopes count '
    $beforeOk = ($null -ne $before) -and $before.StartsWith('before: EnabledScopes count 0 |', [System.StringComparison]::Ordinal)
    Add-NewtonCheck $verdict 'recycle_bin_before' $beforeOk ([string]$before) 'readback_failed'
    $want = '  CN=Partitions,CN=Configuration,' + (Get-NewtonDomainDn ([string]$Values['DnsName']))
    $scopeOk = $false
    $seenHeader = $false
    foreach ($line in $Lines) {
        if ($line -ceq 'after: EnabledScopes:') { $seenHeader = $true; continue }
        if ($seenHeader -and ($line -ceq $want)) { $scopeOk = $true }
        if ($seenHeader -and -not $line.StartsWith('  ', [System.StringComparison]::Ordinal)) { $seenHeader = $false }
    }
    Add-NewtonCheck $verdict 'recycle_bin_scope' $scopeOk $want.Trim() 'readback_failed'
    $feature = Find-NewtonLine $Lines 'msDS-EnabledFeature on Partitions: '
    $featureOk = ($null -ne $feature) -and $feature.Contains('CN=Recycle Bin Feature,CN=Optional Features,')
    Add-NewtonCheck $verdict 'recycle_bin_feature' $featureOk ([string]$feature) 'readback_failed'
    return $verdict
}

function Get-NewtonStage3StateVerdict {
    # The read of a resumed stage 3 (bug hunt R1): 'before'
    # in the measured state of the fresh forest (no scope enabled, the
    # measured FeatureScope and RequiredForestMode, the Recycle Bin not
    # among the features of the Partitions container), 'after' in the
    # measured state Enable-ADOptionalFeature leaves (MEASURED-1.5, stage 3
    # on BUILD1: one scope, the plan's Partitions container, and the
    # Recycle Bin the one enabled feature of that container).  Any other
    # state stops readback_failed.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $partitions = 'CN=Partitions,CN=Configuration,' + (Get-NewtonDomainDn ([string]$Values['DnsName']))
    $feature = 'CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,' +
        (Get-NewtonDomainDn ([string]$Values['DnsName']))
    $formed = $true
    $count = -1
    $countLines = Find-NewtonLines $Lines 'now: EnabledScopes count '
    if (($countLines.Count -eq 1) -and
        ($countLines[0] -cmatch '\Anow: EnabledScopes count ([0-9]+) \| FeatureScope ForestOrConfigurationSet \| RequiredForestMode Windows2008R2Forest\z')) {
        $count = [int]$Matches[1]
    } else {
        $formed = $false
    }
    $scopes = New-Object System.Collections.ArrayList
    $headers = 0
    $inside = $false
    foreach ($line in $Lines) {
        if ($line -ceq 'now: EnabledScopes:') { $headers = $headers + 1; $inside = $true; continue }
        if ($inside) {
            if (-not $line.StartsWith('  ', [System.StringComparison]::Ordinal)) { $inside = $false; continue }
            [void]$scopes.Add($line.Substring(2))
        }
    }
    if ($headers -ne 1) { $formed = $false }
    $featureLines = Find-NewtonLines $Lines 'msDS-EnabledFeature on Partitions: '
    $enabled = $null
    if ($featureLines.Count -eq 1) { $enabled = $featureLines[0].Substring('msDS-EnabledFeature on Partitions: '.Length) } else { $formed = $false }
    if ($formed -and ($count -eq 0) -and ($scopes.Count -eq 0) -and
        (-not $enabled.Contains('CN=Recycle Bin Feature,'))) {
        $verdict['phase'] = 'before'
        Add-NewtonCheck $verdict 'recycle_bin_state' $true 'the state stage 3 was approved on: the Recycle Bin not enabled; s3-recyclebin runs' ''
        return $verdict
    }
    if ($formed -and ($count -eq 1) -and ($scopes.Count -eq 1) -and ($scopes[0] -ceq $partitions) -and ($enabled -ceq $feature)) {
        $verdict['phase'] = 'after'
        Add-NewtonCheck $verdict 'recycle_bin_state' $true 'the state s3-recyclebin leaves; Enable-ADOptionalFeature does not run again' ''
        Add-NewtonCheck $verdict 'recycle_bin_scope' $true $partitions ''
        Add-NewtonCheck $verdict 'recycle_bin_feature' $true ('msDS-EnabledFeature on Partitions: ' + $enabled) ''
        return $verdict
    }
    $detail = 'neither the state before s3-recyclebin nor the one after it: ' +
        'formed ' + [string]$formed + ', scopes ' + [string]$count + ' counted, ' + [string]$scopes.Count + ' listed'
    Add-NewtonCheck $verdict 'recycle_bin_state' $false $detail 'readback_failed'
    return $verdict
}

function Get-NewtonSchemaBlock {
    # The lines of one schema read: 'schema <when> : ...' and the
    # indented lines after it.
    param($Lines, [string]$When)
    $block = New-Object System.Collections.ArrayList
    $inside = $false
    foreach ($line in $Lines) {
        if ($line.StartsWith('schema ' + $When + ' : ', [System.StringComparison]::Ordinal)) { $inside = $true; continue }
        if ($inside) {
            if (-not $line.StartsWith('  ', [System.StringComparison]::Ordinal)) { break }
            [void]$block.Add($line)
        }
    }
    return ,$block.ToArray()
}

function Get-NewtonStage4Verdict {
    # Stage 4: the LAPS schema (absent before, measured; present after
    # with the measured GUIDs), the computer mayContain, the legacy
    # ms-Mcs-AdmPwd still absent, the three explicit SELF ACEs, and the
    # build account out of Enterprise and Schema Admins and still in
    # Domain Admins (stage 9 removes that one).
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $user = [string]$Values['BuildUser']

    $before = Get-NewtonSchemaBlock $Lines 'before'
    $absent = 0
    foreach ($name in $script:LapsAttributes.Keys) {
        if ($before -ccontains ('  ' + $name + ' : absent')) { $absent = $absent + 1 }
    }
    Add-NewtonCheck $verdict 'laps_schema_before' ($absent -eq 6) ('LAPS attributes absent before: ' + [string]$absent + ' of 6') 'readback_failed'

    $after = Get-NewtonSchemaBlock $Lines 'after'
    $schemaOk = $true
    $guids = @{}
    foreach ($name in $script:LapsAttributes.Keys) {
        $ldap = [string]$script:LapsAttributes[$name]
        $pattern = '\A  ' + [regex]::Escape($name) + ' : present, lDAPDisplayName ' + [regex]::Escape($ldap) +
            ', schemaIDGUID (' + $script:GuidPattern + ')\z'
        $found = @($after | Where-Object { $_ -cmatch $pattern })
        if ($found.Count -ne 1) { $schemaOk = $false; continue }
        $null = $found[0] -cmatch $pattern
        $guids[$ldap] = $Matches[1]
    }
    if (@($guids.Values | Sort-Object -Unique).Count -ne $script:LapsAttributes.Count) { $schemaOk = $false }
    Add-NewtonCheck $verdict 'laps_schema' $schemaOk 'the six msLAPS attributes, each with its own schemaIDGUID' 'readback_failed'
    $may = $after -ccontains ('  computer mayContain msLAPS-*: ' + $script:LapsMayContain)
    Add-NewtonCheck $verdict 'laps_maycontain' $may 'the seven msLAPS mayContain of computer' 'readback_failed'
    $legacy = $after -ccontains '  ms-Mcs-AdmPwd : absent'
    Add-NewtonCheck $verdict 'laps_legacy_absent' $legacy 'ms-Mcs-AdmPwd absent' 'readback_failed'

    # The ACEs are read only inside the block of the OU the op names, and
    # that OU is the Domain Controllers OU of the plan's domain.
    $target = 'Set-LapsADComputerSelfPermission: OU=Domain Controllers,' + (Get-NewtonDomainDn ([string]$Values['DnsName']))
    $aceLines = New-Object System.Collections.ArrayList
    $seenTarget = $false
    $inside = $false
    foreach ($line in $Lines) {
        if ($line.StartsWith('Set-LapsADComputerSelfPermission: ', [System.StringComparison]::Ordinal)) {
            $seenTarget = ($line -ceq $target)
            $inside = $false
            continue
        }
        if ($line -ceq 'OU ACEs for SELF:') { $inside = $seenTarget; continue }
        if ($inside) {
            if (-not $line.StartsWith('  ', [System.StringComparison]::Ordinal)) { $inside = $false; continue }
            [void]$aceLines.Add($line)
        }
    }
    $aceOk = $aceLines.Count -gt 0
    foreach ($ace in $script:LapsSelfAces) {
        $object = [string]$ace['object']
        if ($ace.ContainsKey('attribute')) { $object = [string]$guids[[string]$ace['attribute']] }
        if ($object -cnotmatch ('\A' + $script:GuidPattern + '\z')) { $aceOk = $false; continue }
        $pattern = '\A  NT AUTHORITY\\SELF \| ' + [regex]::Escape([string]$ace['rights']) + ' \| Allow \| ObjectType ' +
            [regex]::Escape($object) + ' \([^)]*\) \| InheritanceType Descendents \| InheritedObjectType ' +
            [regex]::Escape($script:ComputerClassGuid) + ' \| IsInherited False\z'
        $seen = $false
        foreach ($line in $aceLines) {
            if ($line -cmatch $pattern) { $seen = $true }
        }
        if (-not $seen) { $aceOk = $false }
    }
    Add-NewtonCheck $verdict 'laps_ace' $aceOk ('the three explicit SELF ACEs on computer objects under ' + $target.Substring('Set-LapsADComputerSelfPermission: '.Length)) 'readback_failed'

    $memberOk = $true
    foreach ($group in @('Enterprise Admins', 'Schema Admins')) {
        if ($null -eq (Find-NewtonLine $Lines ('Remove-ADGroupMember ''' + $group + ''' ' + $user + ': ok'))) { $memberOk = $false }
    }
    $line = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'Get-ADPrincipalGroupMembership after: ') 'Get-ADPrincipalGroupMembership after: '
    $list = @()
    if ($null -eq $line) { $memberOk = $false } else { $list = @($line.Split(',') | ForEach-Object { $_.Trim() }) }
    if ($list -cnotcontains 'Domain Admins') { $memberOk = $false }
    if (($list -ccontains 'Enterprise Admins') -or ($list -ccontains 'Schema Admins')) { $memberOk = $false }
    foreach ($group in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
        $members = Get-NewtonAfterPrefix (Find-NewtonLine $Lines ('  ' + $group + ' members: ')) ('  ' + $group + ' members: ')
        if ($null -eq $members) { $memberOk = $false; continue }
        $names = @($members.Split(',') | ForEach-Object { $_.Trim() })
        $inGroup = $names -ccontains $user
        if (($group -ceq 'Domain Admins') -ne $inGroup) { $memberOk = $false }
    }
    Add-NewtonCheck $verdict 'memberships' $memberOk ([string]$line) 'readback_failed'
    return $verdict
}

function Get-NewtonStage4GroupsVerdict {
    # Stage 4 after its reboot (the maintainer's decision, 2026-11-13): (a) the
    # directory has the build account in neither Enterprise Admins (519)
    # nor Schema Admins (518), and (b) the token of the helper's own S4U
    # key login holds neither SID.  A read that is missing or malformed
    # stops readback_failed and never passes; a read that shows either
    # group stops privileged_groups_remain, and the check names which.
    param($Lines, $Values, $Groups)
    $verdict = New-NewtonVerdict
    $user = [string]$Values['BuildUser']
    $dns = [string]$Values['DnsName']

    # (a) the directory.
    $formed = $true
    $found = New-Object System.Collections.ArrayList
    $domainSid = ''
    $domainLines = Find-NewtonLines $Lines 'domain: '
    if (($domainLines.Count -eq 1) -and
        ($domainLines[0] -cmatch '\Adomain: (\S+) \| DomainSID (S-1-5-21-[0-9]+-[0-9]+-[0-9]+)\z') -and
        ($Matches[1] -eq $dns)) {
        $domainSid = $Matches[2]
    } else {
        $formed = $false
    }
    $memberLines = Find-NewtonLines $Lines 'Get-ADPrincipalGroupMembership: '
    $item = '[^(),]+ \((S-1-[0-9]+(?:-[0-9]+)+)\)'
    if (($memberLines.Count -eq 1) -and
        ($memberLines[0] -cmatch ('\AGet-ADPrincipalGroupMembership: ' + $item + '(?:, ' + $item + ')*\z'))) {
        foreach ($match in [regex]::Matches($memberLines[0], '\((S-1-[0-9]+(?:-[0-9]+)+)\)')) {
            $sid = $match.Groups[1].Value
            if ($sid -cmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-(518|519)\z') {
                [void]$found.Add('member of ' + $sid)
            }
        }
    } else {
        $formed = $false
    }
    if ($formed) {
        foreach ($rid in @('519', '518')) {
            $pattern = '\A  [^()]+ \(' + [regex]::Escape($domainSid + '-' + $rid) + '\) members: (.*)\z'
            $groupLines = @($Lines | Where-Object { $_ -cmatch $pattern })
            if ($groupLines.Count -ne 1) { $formed = $false; continue }
            $null = $groupLines[0] -cmatch $pattern
            $members = @($Matches[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            if ($members -contains $user) { [void]$found.Add($user + ' in ' + $domainSid + '-' + $rid) }
        }
    }
    if (-not $formed) {
        Add-NewtonCheck $verdict 'directory_groups' $false 'the directory read of the groups is missing or malformed' 'readback_failed'
    } elseif ($found.Count -gt 0) {
        Add-NewtonCheck $verdict 'directory_groups' $false ('the directory still holds the build account in Enterprise or Schema Admins: ' + ($found.ToArray() -join '; ')) 'privileged_groups_remain'
    } else {
        Add-NewtonCheck $verdict 'directory_groups' $true 'the build account is in neither Enterprise Admins (519) nor Schema Admins (518)' ''
    }

    # (b) the token of the S4U key login: whoami /groups /fo csv /nh.
    $tokenFormed = $true
    $held = New-Object System.Collections.ArrayList
    $administrators = $false
    $count = 0
    foreach ($line in @($Groups)) {
        $text = [string]$line
        if ($text -eq '') { continue }
        $count = $count + 1
        if ($text -cnotmatch '\A"[^"]*","[^"]*","(S-1-[0-9]+(?:-[0-9]+)+)","[^"]*"\z') { $tokenFormed = $false; continue }
        $sid = $Matches[1]
        if ($sid -ceq 'S-1-5-32-544') { $administrators = $true }
        if ($sid -cmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-(518|519)\z') { [void]$held.Add($sid) }
    }
    if (($count -eq 0) -or (-not $administrators)) { $tokenFormed = $false }
    if (-not $tokenFormed) {
        Add-NewtonCheck $verdict 's4u_token_groups' $false 'the token read of the S4U key login is missing or malformed' 'readback_failed'
    } elseif ($held.Count -gt 0) {
        Add-NewtonCheck $verdict 's4u_token_groups' $false ('the S4U key login still holds: ' + ($held.ToArray() -join ', ')) 'privileged_groups_remain'
    } else {
        Add-NewtonCheck $verdict 's4u_token_groups' $true 'the S4U key login holds neither 518 nor 519' ''
    }
    return $verdict
}

function Get-NewtonLapsAceOk {
    # The three explicit SELF ACEs of the self-permission among the ACE
    # lines of one OU, each to the GUID of its attribute in this forest.
    param($AceLines, $Guids)
    if (@($AceLines).Count -eq 0) { return $false }
    foreach ($ace in $script:LapsSelfAces) {
        $object = [string]$ace['object']
        if ($ace.ContainsKey('attribute')) { $object = [string]$Guids[[string]$ace['attribute']] }
        if ($object -cnotmatch ('\A' + $script:GuidPattern + '\z')) { return $false }
        $pattern = '\A  NT AUTHORITY\\SELF \| ' + [regex]::Escape([string]$ace['rights']) + ' \| Allow \| ObjectType ' +
            [regex]::Escape($object) + ' \([^)]*\) \| InheritanceType Descendents \| InheritedObjectType ' +
            [regex]::Escape($script:ComputerClassGuid) + ' \| IsInherited False\z'
        $seen = $false
        foreach ($line in $AceLines) { if ($line -cmatch $pattern) { $seen = $true } }
        if (-not $seen) { return $false }
    }
    return $true
}

function Get-NewtonStage4StateVerdict {
    # The read of a resumed stage 4 (F1 of the stage 4 triage): 'before'
    # when the six LAPS attributes and the legacy one are all absent, no
    # explicit SELF ACE is on the Domain Controllers OU and the build account
    # is in Domain, Enterprise and Schema Admins (the state s4-laps was
    # approved on), 'after' when the state is the one a
    # successful s4-laps leaves (MEASURED-1.5, "Stages 5 and 6 on BUILD1":
    # the schema with its own GUIDs, the computer mayContain, the legacy
    # attribute absent, the three SELF ACEs on the Domain Controllers OU,
    # the build account in Domain Admins and in neither Enterprise nor
    # Schema Admins).  Any other state stops readback_failed.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $user = [string]$Values['BuildUser']
    $now = Get-NewtonSchemaBlock $Lines 'now'
    $absent = 0
    foreach ($name in (@($script:LapsAttributes.Keys) + @('ms-Mcs-AdmPwd'))) {
        if ($now -ccontains ('  ' + $name + ' : absent')) { $absent = $absent + 1 }
    }
    $target = 'OU read: OU=Domain Controllers,' + (Get-NewtonDomainDn ([string]$Values['DnsName']))
    $aceLines = New-Object System.Collections.ArrayList
    $seenTarget = $false
    $inside = $false
    foreach ($line in $Lines) {
        if ($line.StartsWith('OU read: ', [System.StringComparison]::Ordinal)) { $seenTarget = ($line -ceq $target); $inside = $false; continue }
        if ($line -ceq 'OU ACEs for SELF:') { $inside = $seenTarget; continue }
        if ($inside) {
            if (-not $line.StartsWith('  ', [System.StringComparison]::Ordinal)) { $inside = $false; continue }
            [void]$aceLines.Add($line)
        }
    }
    $line = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'Get-ADPrincipalGroupMembership now: ') 'Get-ADPrincipalGroupMembership now: '
    $list = @()
    if ($null -ne $line) { $list = @($line.Split(',') | ForEach-Object { $_.Trim() }) }
    $members = @{}
    foreach ($group in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
        $found = Get-NewtonAfterPrefix (Find-NewtonLine $Lines ('  ' + $group + ' members: ')) ('  ' + $group + ' members: ')
        if ($null -eq $found) { $members[$group] = $null } else { $members[$group] = @($found.Split(',') | ForEach-Object { $_.Trim() }) }
    }
    if (($absent -eq 7) -and ($now.Count -eq 8)) {
        # The whole measured before-state: no explicit SELF ACE on the
        # Domain Controllers OU, and the build account in Domain,
        # Enterprise and Schema Admins, in the directory and its own list.
        $beforeOk = ($null -ne $line) -and (@($aceLines | Where-Object { $_.EndsWith('| IsInherited False', [System.StringComparison]::Ordinal) }).Count -eq 0)
        # The build account's groups are exactly the measured before-state's.
        if ((@($list | Sort-Object) -join ', ') -cne 'Administrators, Domain Admins, Domain Users, Enterprise Admins, Schema Admins') { $beforeOk = $false }
        foreach ($group in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
            if (($list -cnotcontains $group) -or ($null -eq $members[$group]) -or ($members[$group] -cnotcontains $user)) { $beforeOk = $false }
        }
        if ($beforeOk) {
            $verdict['phase'] = 'before'
            Add-NewtonCheck $verdict 'laps_state' $true 'the state s4-laps was approved on: no LAPS schema, no SELF ACE of its own, the build account in Enterprise and Schema Admins; s4-laps runs' ''
        } else {
            Add-NewtonCheck $verdict 'laps_state' $false 'the LAPS schema is absent but the ACEs or the memberships are not the state before s4-laps' 'readback_failed'
        }
        return $verdict
    }
    $guids = @{}
    $schemaOk = $true
    foreach ($name in $script:LapsAttributes.Keys) {
        $ldap = [string]$script:LapsAttributes[$name]
        $pattern = '\A  ' + [regex]::Escape($name) + ' : present, lDAPDisplayName ' + [regex]::Escape($ldap) +
            ', schemaIDGUID (' + $script:GuidPattern + ')\z'
        $found = @($now | Where-Object { $_ -cmatch $pattern })
        if ($found.Count -ne 1) { $schemaOk = $false; continue }
        $null = $found[0] -cmatch $pattern
        $guids[$ldap] = $Matches[1]
    }
    if (@($guids.Values | Sort-Object -Unique).Count -ne $script:LapsAttributes.Count) { $schemaOk = $false }
    if ($now -cnotcontains ('  computer mayContain msLAPS-*: ' + $script:LapsMayContain)) { $schemaOk = $false }
    if ($now -cnotcontains '  ms-Mcs-AdmPwd : absent') { $schemaOk = $false }

    # Exactly the three explicit SELF ACEs of the self-permission (IC3 of
    # the task 6 triage): an explicit ACE more is not the state s4-laps
    # leaves.  Every measured after-state holds three (MEASURED-1.5).
    $explicit = @($aceLines | Where-Object { $_.EndsWith('| IsInherited False', [System.StringComparison]::Ordinal) })
    $aceOk = (Get-NewtonLapsAceOk -AceLines $aceLines.ToArray() -Guids $guids) -and ($explicit.Count -eq @($script:LapsSelfAces).Count)

    # The build account's groups are exactly the measured set of the
    # after-state (IC3): Administrators, Domain Admins and Domain Users.
    $memberOk = $true
    if ($null -eq $line) { $memberOk = $false }
    if ((@($list | Sort-Object) -join ', ') -cne 'Administrators, Domain Admins, Domain Users') { $memberOk = $false }
    foreach ($group in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
        if ($null -eq $members[$group]) { $memberOk = $false; continue }
        if (($group -ceq 'Domain Admins') -ne ($members[$group] -ccontains $user)) { $memberOk = $false }
    }
    $ok = $schemaOk -and $aceOk -and $memberOk
    if ($ok) {
        $verdict['phase'] = 'after'
        Add-NewtonCheck $verdict 'laps_state' $true 'the state s4-laps leaves: the schema, the SELF ACEs and the memberships; on to the reboot' ''
    } else {
        $detail = 'neither the state before s4-laps nor the one after it: schema ' + [string]$schemaOk + ', ACEs ' + [string]$aceOk + ', memberships ' + [string]$memberOk
        Add-NewtonCheck $verdict 'laps_state' $false $detail 'readback_failed'
    }
    return $verdict
}

function ConvertTo-NewtonDnValue {
    # A name as one RDN value of a DN, escaped as the s5-structure body
    # escapes it.
    param([string]$Value)
    $escaped = [regex]::Replace($Value, '([,\\#+<>;"=])', '\$1')
    if ($escaped.StartsWith(' ')) { $escaped = '\' + $escaped }
    if ($escaped.EndsWith(' ')) { $escaped = $escaped.Substring(0, $escaped.Length - 1) + '\ ' }
    return $escaped
}

function Get-NewtonPolicyLine {
    # The read-back of a password policy as the ops print it, with the
    # baseline's values: the domain's (with no prefix) or a PSO's.
    param($Values, [string]$MinLength)
    $days = { param($n) ([TimeSpan]::FromDays([int]$n)).ToString() }
    $minutes = { param($n) ([TimeSpan]::FromMinutes([int]$n)).ToString() }
    return 'MinPasswordLength ' + $MinLength + ' | PasswordHistoryCount ' + [string]$Values['PasswordHistory'] +
        ' | MaxPasswordAge ' + (& $days $Values['PasswordMaxAgeDays']) + ' | MinPasswordAge ' + (& $days $Values['PasswordMinAgeDays']) +
        ' | ComplexityEnabled ' + [string]$Values['PasswordComplexity'] + ' | ReversibleEncryptionEnabled ' + [string]$Values['PasswordReversible'] +
        ' | LockoutThreshold ' + [string]$Values['LockoutThreshold'] + ' | LockoutDuration ' + (& $minutes $Values['LockoutMinutes']) +
        ' | LockoutObservationWindow ' + (& $minutes $Values['LockoutWindowMinutes'])
}

function Get-NewtonStage5Verdict {
    # Stage 5's read-back (DESIGN-1.5, the stage table: every object and
    # value).  Every check stops readback_failed.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $dns = [string]$Values['DnsName']
    $root = Get-NewtonDomainDn $dns

    $sid = ''
    $domainLines = Find-NewtonLines $Lines 'domain: '
    $domainOk = ($domainLines.Count -eq 1) -and
        ($domainLines[0] -cmatch '\Adomain: (\S+) \| DomainSID (S-1-5-21-[0-9]+-[0-9]+-[0-9]+)\z') -and ($Matches[1] -eq $dns)
    if ($domainOk) { $sid = $Matches[2] }
    Add-NewtonCheck $verdict 'domain' $domainOk ([string]$(if ($domainLines.Count -gt 0) { $domainLines[0] })) 'readback_failed'

    $secretOk = ($Lines -ccontains 'admin secret file deleted: True')
    Add-NewtonCheck $verdict 'secret_files' $secretOk 'the DPAPI file of the admin secret deleted by the op' 'readback_failed'

    $ousOk = $true
    $wanted = New-Object System.Collections.ArrayList
    foreach ($path in @($Values['OuTree'])) {
        $parent = $root
        foreach ($name in ([string]$path).Split('/')) {
            $dn = 'OU=' + (ConvertTo-NewtonDnValue $name) + ',' + $parent
            if (-not $wanted.Contains($dn)) { [void]$wanted.Add($dn) }
            $parent = $dn
        }
    }
    foreach ($dn in $wanted) {
        if (@($Lines | Where-Object { $_ -ceq ('  OU ' + $dn + ' | Protected True') }).Count -ne 1) { $ousOk = $false }
    }
    Add-NewtonCheck $verdict 'ous' $ousOk ([string]$wanted.Count + ' OUs, each protected from accidental deletion') 'readback_failed'

    $groupsOk = $true
    foreach ($group in @($Values['Groups'])) {
        $want = '  group ' + $group + ' | Global | Security | CN=' + (ConvertTo-NewtonDnValue $group) + ',CN=Users,' + $root
        if (@($Lines | Where-Object { $_ -ceq $want }).Count -ne 1) { $groupsOk = $false }
    }
    Add-NewtonCheck $verdict 'groups' $groupsOk ([string]@($Values['Groups']).Count + ' global security groups in CN=Users') 'readback_failed'

    $owner = [string]$Values['OwnerAdmin']
    $ownerPattern = '\A  owner admin ' + [regex]::Escape($owner) + ' \| Enabled True \| UPN ' + [regex]::Escape($owner + '@' + $dns) +
        ' \| pwdLastSet 0 \| ' + [regex]::Escape('CN=' + (ConvertTo-NewtonDnValue $owner) + ',CN=Users,' + $root) + '\z'
    $ownerOk = @($Lines | Where-Object { $_ -cmatch $ownerPattern }).Count -eq 1
    Add-NewtonCheck $verdict 'owner_admin' $ownerOk ('the owner admin ' + $owner + ', enabled, to change its password at first logon') 'readback_failed'

    $groupLine = Get-NewtonAfterPrefix (Find-NewtonLine $Lines '  owner admin groups: ') '  owner admin groups: '
    # Exactly Domain Admins, Domain Users (the primary group) and Protected
    # Users: a group more is a wider account than the plan approved.
    $ownerGroupsOk = $false
    if (($sid -ne '') -and ($null -ne $groupLine)) {
        $sids = @([regex]::Matches($groupLine, '\((S-1-[0-9-]+)\)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
        $want = @(($sid + '-512'), ($sid + '-513'), ($sid + '-525')) | Sort-Object
        $ownerGroupsOk = (($sids -join ' ') -ceq ($want -join ' '))
    }
    Add-NewtonCheck $verdict 'owner_admin_groups' $ownerGroupsOk 'the owner admin in Domain Admins (512), Domain Users (513) and Protected Users (525) only' 'readback_failed'

    # The NOT_DELEGATED bit (0x100000) of the userAccountControl of the
    # owner admin: the account is sensitive and cannot be delegated.  The
    # value the op read is the proof; the flag it printed must agree
    # with it.
    $uacLine = Find-NewtonLine $Lines '  owner admin UAC '
    $notDelegatedOk = $false
    $uacDetail = 'the NOT_DELEGATED bit (0x100000) of the userAccountControl of the owner admin'
    if ($null -ne $uacLine) {
        $uacMatch = [regex]::Match([string]$uacLine, '\A  owner admin UAC (?<uac>[0-9]+) \| NOT_DELEGATED (?<flag>True|False)\z')
        if ($uacMatch.Success) {
            $uac = [int64]$uacMatch.Groups['uac'].Value
            $flag = $uacMatch.Groups['flag'].Value
            $notDelegatedOk = (($uac -band 0x100000) -ne 0) -and ($flag -ceq 'True')
            $uacDetail = 'the userAccountControl of the owner admin is ' + $uac + ', NOT_DELEGATED ' + $flag
        }
    }
    Add-NewtonCheck $verdict 'owner_admin_not_delegated' $notDelegatedOk $uacDetail 'readback_failed'

    # The machine account quota of the domain head (AD-A-44): 0 after the
    # write of stage 5.  The check names the quota before and the one
    # after.
    $quotaBefore = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'machine account quota before: ') 'machine account quota before: '
    $quotaAfter = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'machine account quota after: ') 'machine account quota after: '
    $quotaOk = ($null -ne $quotaBefore) -and ($null -ne $quotaAfter) -and
        ($quotaBefore -cmatch '\A[0-9]{1,10}\z') -and ($quotaAfter -ceq '0')
    Add-NewtonCheck $verdict 'machine_account_quota' $quotaOk ('the machine account quota of the domain: before ' + [string]$quotaBefore + ', after ' + [string]$quotaAfter) 'readback_failed'

    $policy = '  password policy: ' + (Get-NewtonPolicyLine -Values $Values -MinLength ([string]$Values['PasswordMinLength']))
    Add-NewtonCheck $verdict 'password_policy' ($Lines -ccontains $policy) $policy.Trim() 'readback_failed'

    $pso = '  PSO ' + [string]$Values['PsoName'] + ' | Precedence ' + [string]$Values['PsoPrecedence'] + ' | ' +
        (Get-NewtonPolicyLine -Values $Values -MinLength ([string]$Values['PsoMinLength']))
    $applies = Get-NewtonAfterPrefix (Find-NewtonLine $Lines '  PSO applies to: ') '  PSO applies to: '
    $psoOk = ($Lines -ccontains $pso) -and ($applies -ceq ('CN=Domain Admins,CN=Users,' + $root))
    Add-NewtonCheck $verdict 'admin_pso' $psoOk $pso.Trim() 'readback_failed'

    $option = [string]$Values['AdministratorOption']
    $builtinOk = $false
    $builtinLines = Find-NewtonLines $Lines '  built-in Administrator '
    $start = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'task start ') 'task start '
    if (($sid -ne '') -and ($builtinLines.Count -eq 1) -and
        ($builtinLines[0] -cmatch ('\A  built-in Administrator \S+ \(' + [regex]::Escape($sid + '-500') + '\) \| Enabled (True|False) \| PasswordLastSet (\S+)\z'))) {
        $enabled = $Matches[1]
        $setText = $Matches[2]
        $culture = [Globalization.CultureInfo]::InvariantCulture
        $styles = [Globalization.DateTimeStyles]::RoundtripKind
        $set = [DateTime]::MinValue
        $began = [DateTime]::MinValue
        if ($option -ceq 'random-password') {
            $builtinOk = ($Lines -ccontains 'built-in Administrator: password reset') -and ($enabled -ceq 'True') -and
                ($null -ne $start) -and [DateTime]::TryParse($setText, $culture, $styles, [ref]$set) -and
                [DateTime]::TryParse($start, $culture, $styles, [ref]$began) -and
                ($set.ToUniversalTime() -ge $began.ToUniversalTime())
        } elseif ($option -ceq 'disabled') {
            $builtinOk = ($Lines -ccontains 'built-in Administrator: disabled') -and ($enabled -ceq 'False')
        }
    }
    Add-NewtonCheck $verdict 'builtin_administrator' $builtinOk ('the built-in Administrator (RID 500): ' + $option) 'readback_failed'

    if ($option -ceq 'disabled') {
        # The built-in Administrator (RID 500) is a member of Protected
        # Users (RID 525) as well: the read-back of the stage proves the
        # membership, and the audit findings that skip a member of that
        # group (AD-A-06, AD-A-09) skip the account.
        $protectedOk = $false
        $protectedLine = Find-NewtonLine $Lines '  protected users: '
        if (($sid -ne '') -and ($null -ne $protectedLine)) {
            $protectedOk = ($protectedLine -cmatch ('\A  protected users: \S+ \(' + [regex]::Escape($sid + '-500') + '\) \| member\z'))
        }
        Add-NewtonCheck $verdict 'builtin_administrator_protected_users' $protectedOk 'the built-in Administrator (RID 500) is a member of Protected Users (525)' 'readback_failed'
    }
    return $verdict
}

function Get-NewtonGpoSettingParts {
    param([string]$Setting)
    $part = $Setting.Split('|')
    return @{ key = $part[0]; name = $part[1]; value = $part[2] }
}

function Get-NewtonStage6GpoVerdict {
    # One baseline GPO: not there before, created, each value set, read
    # back from the GPO, its versions written (DS and SYSVOL equal, more
    # than 0), linked and enabled on its target.  One check per GPO.
    param($Lines, $Values, [string]$Gpo)
    $verdict = New-NewtonVerdict
    $prefix = 'Domain'
    if ($Gpo -ceq 'dc') { $prefix = 'Dc' }
    $name = [string]$Values[$prefix + 'GpoName']
    $root = Get-NewtonDomainDn ([string]$Values['DnsName'])
    $target = $root
    if ($Gpo -ceq 'dc') { $target = 'OU=Domain Controllers,' + $root }
    $problems = New-Object System.Collections.ArrayList
    if ($Lines -cnotcontains ('domain: ' + [string]$Values['DnsName'] + ' | target ' + $target)) { [void]$problems.Add('target') }
    if ($Lines -cnotcontains 'before: GPOs of the name: 0') { [void]$problems.Add('a GPO of the name was there before') }
    $id = ''
    $created = @($Lines | Where-Object { $_ -cmatch ('\ANew-GPO: ' + [regex]::Escape($name) + ' \| Id (' + $script:GuidPattern + ')\z') })
    if ($created.Count -eq 1) { $null = $created[0] -cmatch ('\| Id (' + $script:GuidPattern + ')\z'); $id = $Matches[1] } else { [void]$problems.Add('New-GPO') }
    foreach ($setting in @($Values[$prefix + 'GpoSettings'])) {
        $p = Get-NewtonGpoSettingParts $setting
        if ($Lines -cnotcontains ('Set-GPRegistryValue ' + $p.key + '\' + $p.name + ' = ' + $p.value + ': ok')) { [void]$problems.Add('set ' + $p.name) }
        if ($Lines -cnotcontains ('  GPO value ' + $p.key + '\' + $p.name + ' = ' + $p.value + ' | DWord | Set')) { [void]$problems.Add('value ' + $p.name) }
    }
    $versionPattern = '\A  GPO ' + [regex]::Escape($name) + ' \| Id ' + [regex]::Escape($id) +
        ' \| GpoStatus AllSettingsEnabled \| Computer DSVersion ([0-9]+) SysvolVersion ([0-9]+) \| User DSVersion [0-9]+ SysvolVersion [0-9]+\z'
    $versions = @($Lines | Where-Object { $_ -cmatch $versionPattern })
    if (($versions.Count -ne 1) -or ($id -eq '')) {
        [void]$problems.Add('versions')
    } else {
        $null = $versions[0] -cmatch $versionPattern
        if (($Matches[1] -ne $Matches[2]) -or ([int]$Matches[1] -lt 1)) { [void]$problems.Add('versions') }
    }
    $link = @($Lines | Where-Object { $_ -cmatch ('\A  link ' + [regex]::Escape($name) + ' \| Enabled True \| Enforced False \| Order [0-9]+\z') })
    if ($link.Count -ne 1) { [void]$problems.Add('link') }
    $linked = @($Lines | Where-Object { $_ -cmatch ('\ANew-GPLink: ' + [regex]::Escape($name) + ' \| Target ' + [regex]::Escape($target) + ' \| Enabled True \| Order [0-9]+\z') })
    if ($linked.Count -ne 1) { [void]$problems.Add('New-GPLink') }
    $detail = $name + ' linked to ' + $target
    if ($problems.Count -gt 0) { $detail = $name + ': ' + ($problems.ToArray() -join ', ') }
    Add-NewtonCheck $verdict ('gpo_' + $Gpo) ($problems.Count -eq 0) $detail 'readback_failed'
    return $verdict
}

function Get-NewtonSeceditSection {
    # The key = value pairs of one section of the secedit export lines.
    param($Lines, [string]$Section)
    $pairs = @{}
    $inside = $false
    $seen = $false
    foreach ($line in $Lines) {
        if (-not $line.StartsWith('secedit ', [System.StringComparison]::Ordinal)) { continue }
        $text = $line.Substring(8)
        if ($text.StartsWith('[', [System.StringComparison]::Ordinal)) { $inside = ($text -ceq ('[' + $Section + ']')); if ($inside) { $seen = $true }; continue }
        if ($inside -and ($text -cmatch '\A([A-Za-z]+) = (.*)\z')) { $pairs[$Matches[1]] = $Matches[2] }
    }
    if (-not $seen) { return $null }
    return $pairs
}

function Get-NewtonStage6ReadVerdict {
    # Stage 6's read of the applied policy: the refresh, every baseline
    # registry value on DC1, the account policy in the secedit export,
    # the domain's password policy after the refresh (stage 5's, not
    # undone by it), and each GPO's DS and SYSVOL versions equal.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    Add-NewtonCheck $verdict 'gpupdate' ($Lines -ccontains 'gpupdate /target:computer /force exit 0') 'gpupdate /target:computer /force' 'readback_failed'

    $missing = New-Object System.Collections.ArrayList
    foreach ($setting in @($Values['GpoSettings'])) {
        $p = Get-NewtonGpoSettingParts $setting
        if ($Lines -cnotcontains ('registry ' + $p.key + '\' + $p.name + ' = ' + $p.value)) { [void]$missing.Add($p.name) }
    }
    $detail = 'every baseline value in the registry of DC1'
    if ($missing.Count -gt 0) { $detail = 'not as the baseline: ' + ($missing.ToArray() -join ', ') }
    Add-NewtonCheck $verdict 'registry' ($missing.Count -eq 0) $detail 'readback_failed'

    $access = Get-NewtonSeceditSection -Lines $Lines -Section 'System Access'
    $want = [ordered]@{
        MinimumPasswordAge = [string]$Values['PasswordMinAgeDays']
        MaximumPasswordAge = [string]$Values['PasswordMaxAgeDays']
        MinimumPasswordLength = [string]$Values['PasswordMinLength']
        PasswordComplexity = $(if ([string]$Values['PasswordComplexity'] -ceq 'True') { '1' } else { '0' })
        PasswordHistorySize = [string]$Values['PasswordHistory']
        LockoutBadCount = [string]$Values['LockoutThreshold']
        ResetLockoutCount = [string]$Values['LockoutWindowMinutes']
        LockoutDuration = [string]$Values['LockoutMinutes']
        ClearTextPassword = $(if ([string]$Values['PasswordReversible'] -ceq 'True') { '1' } else { '0' })
    }
    $wrong = New-Object System.Collections.ArrayList
    if ($null -eq $access) {
        [void]$wrong.Add('no [System Access] section')
    } else {
        foreach ($key in $want.Keys) {
            if ((-not $access.ContainsKey($key)) -or ([string]$access[$key] -cne [string]$want[$key])) { [void]$wrong.Add($key) }
        }
    }
    $detail = 'the account policy of the export is the baseline'
    if ($wrong.Count -gt 0) { $detail = 'secedit [System Access] not as the baseline: ' + ($wrong.ToArray() -join ', ') }
    Add-NewtonCheck $verdict 'secedit_password_policy' ($wrong.Count -eq 0) $detail 'readback_failed'

    # The export's [Registry Values] lists the security options DC1
    # applies, each as MACHINE\<key>\<name>=4,<DWORD> (measured: secedit
    # writes LanManServer in its own case, so the path is compared
    # without case and the value exactly).  The export holds the values
    # of the security template only: the Windows LAPS policy is not one
    # of them, and the read of the registry proves that one.
    $registry = @{}
    $inRegistry = $false
    $seenRegistry = $false
    foreach ($line in $Lines) {
        if (-not $line.StartsWith('secedit ', [System.StringComparison]::Ordinal)) { continue }
        $text = $line.Substring(8)
        if ($text.StartsWith('[', [System.StringComparison]::Ordinal)) { $inRegistry = ($text -ceq '[Registry Values]'); if ($inRegistry) { $seenRegistry = $true }; continue }
        if ($inRegistry -and ($text -cmatch '\A(MACHINE\\[^=]+)=(.*)\z')) { $registry[$Matches[1].ToLowerInvariant()] = $Matches[2] }
    }
    $absent = New-Object System.Collections.ArrayList
    foreach ($setting in @($Values['SecurityGpoSettings'])) {
        $p = Get-NewtonGpoSettingParts $setting
        $path = ('MACHINE' + $p.key.Substring(4) + '\' + $p.name).ToLowerInvariant()
        if ((-not $seenRegistry) -or (-not $registry.ContainsKey($path)) -or ([string]$registry[$path] -cne ('4,' + $p.value))) { [void]$absent.Add($p.name) }
    }
    $detail = 'every value of the security template in the [Registry Values] of the export'
    if ($absent.Count -gt 0) { $detail = 'secedit [Registry Values] not as the baseline: ' + ($absent.ToArray() -join ', ') }
    Add-NewtonCheck $verdict 'secedit_registry_values' ($absent.Count -eq 0) $detail 'readback_failed'

    $policy = 'password policy: ' + (Get-NewtonPolicyLine -Values $Values -MinLength ([string]$Values['PasswordMinLength']))
    Add-NewtonCheck $verdict 'password_policy_after_refresh' ($Lines -ccontains $policy) $policy 'readback_failed'

    $versionsOk = $true
    foreach ($name in @($Values['GpoNames'])) {
        $pattern = '\AGPO ' + [regex]::Escape([string]$name) + ' \| GpoStatus AllSettingsEnabled \| Computer DSVersion ([0-9]+) SysvolVersion ([0-9]+)\z'
        $found = @($Lines | Where-Object { $_ -cmatch $pattern })
        if ($found.Count -ne 1) { $versionsOk = $false; continue }
        $null = $found[0] -cmatch $pattern
        if (($Matches[1] -ne $Matches[2]) -or ([int]$Matches[1] -lt 1)) { $versionsOk = $false }
    }
    Add-NewtonCheck $verdict 'gpo_versions' $versionsOk 'each baseline GPO with its DS and SYSVOL versions equal' 'readback_failed'

    # Windows LAPS on the domain controllers (AD-A-46): the computer
    # object of DC1 carries the LAPS password, so the policy processing
    # wrote it and the policy of the DC GPO is in force.
    $lapsLine = Find-NewtonLine $Lines '  computer object '
    $lapsOk = $false
    $lapsDetail = 'the LAPS password of the computer object of DC1 (msLAPS-PasswordExpirationTime)'
    if ($null -ne $lapsLine) {
        $lapsMatch = [regex]::Match([string]$lapsLine, '\A  computer object (?<host>\S+) \| msLAPS-PasswordExpirationTime (?<expiry>[0-9]*) \| msLAPS-EncryptedDSRMPassword (?<dsrm>present|absent)\z')
        if ($lapsMatch.Success) {
            # An unset expiration time prints empty (a DC may carry the
            # encrypted DSRM password only): read as 0.
            $expiry = [int64]0
            if ($lapsMatch.Groups['expiry'].Value -ne '') { $expiry = [int64]$lapsMatch.Groups['expiry'].Value }
            $dsrm = $lapsMatch.Groups['dsrm'].Value
            $lapsOk = ($expiry -ne 0) -or ($dsrm -ceq 'present')
            $lapsDetail = 'the computer object ' + $lapsMatch.Groups['host'].Value + ': msLAPS-PasswordExpirationTime ' + $expiry + ', msLAPS-EncryptedDSRMPassword ' + $dsrm
        }
    }
    Add-NewtonCheck $verdict 'laps' $lapsOk $lapsDetail 'readback_failed'
    return $verdict
}

function Get-NewtonStage9DaVerdict {
    # newton-build is out of Domain Admins in the directory: the read after
    # the removal says 0.  A read that is missing stops readback_failed.
    param($Lines)
    $verdict = New-NewtonVerdict
    $before = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'member before: ') 'member before: '
    $after = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'member after: ') 'member after: '
    if (($null -eq $before) -or ($null -eq $after) -or ($before -cnotmatch '\A[0-9]{1,3}\z')) {
        Add-NewtonCheck $verdict 'domain_admins' $false 'the read of Domain Admins is missing' 'readback_failed'
        return $verdict
    }
    Add-NewtonCheck $verdict 'domain_admins' ($after -ceq '0') ('member before ' + $before + ', after ' + $after) 'readback_failed'
    return $verdict
}

function Get-NewtonStage9RegisterVerdict {
    # The cleanup task is registered as SYSTEM and runs (measured: state
    # Running two seconds after the start; the script waits before it acts).
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $task = [string]$Values['CleanupTask']
    $registered = Find-NewtonLine $Lines ('registered ' + $task + ' as ')
    $state = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'state ') 'state '
    $ok = ($registered -ceq ('registered ' + $task + ' as SYSTEM LogonType ServiceAccount')) -and ($state -ceq 'Running')
    Add-NewtonCheck $verdict 'cleanup_task' $ok ('registered ' + [string]($null -ne $registered) + ', state ' + [string]$state) 'op_failed'
    return $verdict
}

function Get-NewtonStage8SetupVerdict {
    # A filled setup of stage 8 ran to its end: the op ran the script the
    # helper wrote (its sha256), every step of the generator printed its
    # line, in order, and the setup's own last lines name the plan's key
    # (and, for the write setup, the plan's write helper and K's
    # fingerprint).  Anything else stops op_failed.
    param([string]$Op, $Lines, $Values)
    $verdict = New-NewtonVerdict
    $ran = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'setup script: ') 'setup script: '
    $wanted = [string]$Values['SetupScript'] + ', sha256 ' + [string]$Values['SetupSha']
    Add-NewtonCheck $verdict ($Op + '_script') ($ran -ceq $wanted) ('setup script ' + [string]$ran) 'op_failed'
    $at = -1
    $inOrder = $true
    $missing = ''
    foreach ($step in $script:SetupSteps[$Op]) {
        $found = -1
        for ($index = $at + 1; $index -lt $Lines.Count; $index++) {
            if ([string]$Lines[$index] -ceq $step) { $found = $index; break }
        }
        if ($found -lt 0) { $inOrder = $false; $missing = $step; break }
        $at = $found
    }
    $stepDetail = 'every step, in order'
    if (-not $inOrder) { $stepDetail = 'missing or out of order: ' + $missing }
    Add-NewtonCheck $verdict ($Op + '_steps') $inOrder $stepDetail 'op_failed'
    # The 1.4 setup leaves with 'exit 1' on some refusals: a step line
    # printed before it does not make the setup a pass.
    $exit = Find-NewtonLine $Lines 'setup exit '
    Add-NewtonCheck $verdict ($Op + '_exit') ($exit -ceq 'setup exit 0') ([string]$exit) 'op_failed'
    $key = [string]$Values['OpsKey']
    if ($Op -ceq 's8-audit') { $key = [string]$Values['AuditKey'] }
    $keySha = Get-NewtonSha256Hex ([Text.Encoding]::UTF8.GetBytes($key))
    $keyLine = Find-NewtonLine $Lines 'The installed public key (sha256): '
    Add-NewtonCheck $verdict ($Op + '_key') ($keyLine -ceq ('The installed public key (sha256): ' + $keySha)) ([string]$keyLine) 'op_failed'
    if ($Op -ceq 's8-ops') {
        $helperLine = Find-NewtonLine $Lines 'sha256 write.ps1 '
        Add-NewtonCheck $verdict 'write_helper' ($helperLine -ceq ('sha256 write.ps1 ' + [string]$Values['WriteHelperSha'])) ([string]$helperLine) 'op_failed'
        $fingerprintLine = Find-NewtonLine $Lines 'The approval key is installed. Its fingerprint is '
        $fingerprint = Get-NewtonApprovalFingerprint -Key (Get-NewtonKeyBytes)
        Add-NewtonCheck $verdict 'approval_key' ($fingerprintLine -ceq ('The approval key is installed. Its fingerprint is ' + $fingerprint)) 'the fingerprint of the installed key against the build key' 'op_failed'
    }
    return $verdict
}

function Get-NewtonStage8RestartVerdict {
    # The sshd restart task is registered as SYSTEM and runs.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $task = [string]$Values['RestartTask']
    $registered = Find-NewtonLine $Lines ('registered ' + $task + ' as ')
    $state = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'state ') 'state '
    $ok = ($registered -ceq ('registered ' + $task + ' as SYSTEM LogonType ServiceAccount')) -and (@('Running', 'Ready') -ccontains $state)
    Add-NewtonCheck $verdict 'sshd_restart_task' $ok ('registered ' + [string]($null -ne $registered) + ', state ' + [string]$state) 'op_failed'
    return $verdict
}

function Test-NewtonPrivilegedSid {
    # The privileged set of SPEC-1.4 section 5, as the setups read it.
    param([string]$Sid)
    if ($script:OpsPrivilegedBuiltins -ccontains $Sid) { return $true }
    if ($Sid -cnotmatch '\AS-1-5-21-[0-9-]+\z') { return $false }
    return ($script:OpsPrivilegedRids -ccontains ($Sid.Split('-')[-1]))
}

function Get-NewtonStage8ReadVerdict {
    # Stage 8 read back after sshd came back (the maintainer's decisions R1 and on open
    # points 34 and 37): both logins in the sshd configuration once each,
    # with the plan's keys in their keys files; the write helper on disk is
    # the plan's; the write path's K is the build key; sshd runs and
    # answers; newton-audit holds no privileged group; newton-ops holds
    # explicit ACEs on the plan's top-level OUs and the domain head (the
    # machine account quota of the 1.4 delegation) and nowhere else in the
    # domain partition.  A line that is missing fails its check.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    foreach ($pair in @(@('ops_login', 'newton-ops', 'ops keys: ', 'OpsKey'), @('audit_login', 'newton-audit', 'audit keys: ', 'AuditKey'))) {
        $count = Get-NewtonAfterPrefix (Find-NewtonLine $Lines ('sshd match ' + $pair[1] + ': ')) ('sshd match ' + $pair[1] + ': ')
        $keys = Get-NewtonAfterPrefix (Find-NewtonLine $Lines $pair[2]) $pair[2]
        $ok = ($count -ceq '1') -and ($keys -ceq ('restrict ' + [string]$Values[$pair[3]]))
        Add-NewtonCheck $verdict $pair[0] $ok ('Match blocks ' + [string]$count + ', keys file ' + [string]($keys -ceq ('restrict ' + [string]$Values[$pair[3]]))) 'readback_failed'
    }
    $sha = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'write helper sha256: ') 'write helper sha256: '
    Add-NewtonCheck $verdict 'write_helper' ($sha -ceq [string]$Values['WriteHelperSha']) ('on disk ' + [string]$sha) 'readback_failed'
    $shared = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'approval key is the build key: ') 'approval key is the build key: '
    Add-NewtonCheck $verdict 'approval_key' ($shared -ceq 'True') ('the write path K is the build key: ' + [string]$shared) 'readback_failed'
    $service = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'sshd service: ') 'sshd service: '
    $banner = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'sshd banner: ') 'sshd banner: '
    $answers = ($service -ceq 'Running') -and ($null -ne $banner) -and $banner.StartsWith('SSH-2.0-', [System.StringComparison]::Ordinal)
    Add-NewtonCheck $verdict 'sshd_answers' $answers ('service ' + [string]$service + ', banner ' + [string]$banner) 'readback_failed'
    $groups = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'audit token groups: ') 'audit token groups: '
    $privileged = New-Object System.Collections.ArrayList
    $readable = ($null -ne $groups) -and ($groups -cmatch '\AS-1-[0-9-]+(?:,S-1-[0-9-]+)*\z')
    if ($readable) {
        foreach ($sid in $groups.Split(',')) { if (Test-NewtonPrivilegedSid $sid) { [void]$privileged.Add($sid) } }
    }
    $auditDetail = 'the groups of newton-audit were not read'
    if ($readable) { $auditDetail = 'privileged groups: ' + [string]$privileged.Count }
    Add-NewtonCheck $verdict 'audit_unprivileged' ($readable -and ($privileged.Count -eq 0)) $auditDetail 'readback_failed'
    $scan = Find-NewtonLine $Lines 'ops ace scan: '
    $held = New-Object System.Collections.ArrayList
    foreach ($line in (Find-NewtonLines $Lines 'ops explicit aces: ')) {
        $rest = Get-NewtonAfterPrefix $line 'ops explicit aces: '
        [void]$held.Add(($rest -split ' \| ', 2)[0].ToUpperInvariant())
    }
    $expected = New-Object System.Collections.ArrayList
    foreach ($dn in @($Values['OpsOus']) + @([string]$Values['DomainDn'])) { [void]$expected.Add(([string]$dn).ToUpperInvariant()) }
    $sameSet = ($held.Count -eq $expected.Count)
    foreach ($dn in $expected) { if ($held -cnotcontains $dn) { $sameSet = $false } }
    $delegationOk = ($null -ne $scan) -and $sameSet
    $delegationDetail = 'explicit ACEs of newton-ops on ' + [string]$held.Count + ' object(s), ' + [string]$expected.Count + ' expected'
    if ($null -eq $scan) { $delegationDetail = 'the ACE scan did not end' }
    Add-NewtonCheck $verdict 'ops_delegation' $delegationOk $delegationDetail 'readback_failed'
    return $verdict
}

function Get-NewtonStage8SshdVerdict {
    # The sshd restart task's own result: sshd accepted its configuration,
    # restarted (a new process) and runs.
    param([int]$Result, [string]$Output)
    $verdict = New-NewtonVerdict
    $lines = Get-NewtonOutputLines $Output
    $restarted = Find-NewtonLine $lines 'sshd restarted: '
    Add-NewtonCheck $verdict 'sshd_restart' ($Result -eq 0) ('exit ' + [string]$Result + ' | ' + [string]$restarted) 'op_failed'
    return $verdict
}

# ---------------------------------------------------------------------------
# the parsers of stage 7 (MEASURED-1.5 "Stage 7 on BUILD1 and BUILD2")
# ---------------------------------------------------------------------------

function Test-NewtonLineIs {
    # The line of the output that starts with the prefix is the expected
    # line, compared without case (djoin and whoami echo names in their own
    # case).
    param($Lines, [string]$Prefix, [string]$Expected)
    $line = Find-NewtonLine $Lines $Prefix
    if ($null -eq $line) { return $false }
    return ([string]$line).Equals($Expected, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-NewtonStage7ProvisionVerdict {
    # djoin /provision made DC2's computer object in CN=Computers and saved
    # the blob (UTF-16LE with a byte order mark, as measured).
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $dn = Get-NewtonDomainDn ([string]$Values['DnsName'])
    $dc2 = [string]$Values['Dc2Host']
    $blob = [string]$Values['BlobFile']
    $absent = 'before: no computer ' + $dc2 + ' (Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException)'
    $before = Test-NewtonLineIs $Lines 'before: ' $absent
    if ((-not $before) -and ([string]$Values['Reuse'] -ceq '1')) {
        # a resume plan's provision again: the object of the earlier one
        $before = Test-NewtonLineIs $Lines 'before: ' ('before: CN=' + $dc2 + ',CN=Computers,' + $dn)
    }
    Add-NewtonCheck $verdict 'computer_before' $before ([string](Find-NewtonLine $Lines 'before: ')) 'readback_failed'
    $exit = Find-NewtonLine $Lines 'djoin /provision exit '
    $ran = ($null -ne $exit) -and ([string]$exit -cmatch '\Adjoin /provision exit 0 in [0-9]+ s, [0-9]+ lines:\z')
    $made = $null -ne (Find-NewtonLine $Lines ('  [Successfully provisioned [' + $dc2 + '] in the domain [' + [string]$Values['DnsName'] + '].]'))
    if (-not $made) {
        foreach ($line in $Lines) {
            if (([string]$line).Equals(('  [Successfully provisioned [' + $dc2 + '] in the domain [' + [string]$Values['DnsName'] + '].]'), [System.StringComparison]::OrdinalIgnoreCase)) { $made = $true }
        }
    }
    $saved = $null -ne (Find-NewtonLine $Lines ('  [Provisioning data was saved successfully to [' + $blob + '].]'))
    Add-NewtonCheck $verdict 'djoin_provision' ($ran -and $made -and $saved) ([string]$exit) 'op_failed'
    $size = Get-NewtonAfterPrefix (Find-NewtonLine $Lines ('blob: ' + $blob + ', bytes ')) ('blob: ' + $blob + ', bytes ')
    $sizeOk = ($null -ne $size) -and ([string]$size -cmatch '\A[0-9]{1,6}\z') -and ([int]$size -ge 2) -and ([int]$size -le $script:OdjMaxBytes)
    $bom = Test-NewtonLineIs $Lines 'blob first two bytes: ' 'blob first two bytes: ff fe'
    Add-NewtonCheck $verdict 'blob' ($sizeOk -and $bom) ('bytes ' + [string]$size) 'readback_failed'
    $computer = Find-NewtonLine $Lines 'computer: '
    $computerOk = $false
    if ($null -ne $computer) {
        $pattern = '\Acomputer: (.+) \| userAccountControl 4096 \| primaryGroupID 515 \| pwdLastSet [0-9]+ \| dNSHostName (.+)\z'
        if ([string]$computer -cmatch $pattern) {
            $computerOk = ($Matches[1]).Equals(('CN=' + $dc2 + ',CN=Computers,' + $dn), [System.StringComparison]::OrdinalIgnoreCase) -and
                ($Matches[2]).Equals(($dc2 + '.' + [string]$Values['DnsName']), [System.StringComparison]::OrdinalIgnoreCase)
        }
    }
    Add-NewtonCheck $verdict 'computer' $computerOk ([string]$computer) 'readback_failed'
    $all = $true
    foreach ($check in $verdict['checks']) { if (-not [bool]$check['ok']) { $all = $false } }
    $verdict['checks'].Insert(0, [ordered]@{ name = 's7_provision'; ok = $all; detail = 'djoin /provision of ' + $dc2 })
    return $verdict
}

function Get-NewtonStage7InstallVerdict {
    # Install-ADDSDomainController over WinRM succeeded, DC2's computer
    # object moved to the Domain Controllers OU as a DC, the DSRM file went,
    # and DC2's restart was asked for in the same session.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $dn = Get-NewtonDomainDn ([string]$Values['DnsName'])
    $dc2 = [string]$Values['Dc2Host']
    $wsman = Find-NewtonLine $Lines 'Test-WSMan Kerberos: ProductVersion '
    Add-NewtonCheck $verdict 'winrm' ($null -ne $wsman) ([string]$wsman) 'op_failed'
    $before = Find-NewtonLine $Lines 'before: '
    $beforeOk = $false
    if (($null -ne $before) -and ([string]$before -cmatch '\Abefore: (.+) \| pwdLastSet [0-9]+ \| userAccountControl 4096 \| primaryGroupID 515\z')) {
        $beforeOk = ($Matches[1]).Equals(('CN=' + $dc2 + ',CN=Computers,' + $dn), [System.StringComparison]::OrdinalIgnoreCase)
    }
    Add-NewtonCheck $verdict 'member_before' $beforeOk ([string]$before) 'readback_failed'
    $dsrm = Test-NewtonLineIs $Lines 'dsrm.bin deleted on ' ('dsrm.bin deleted on ' + $dc2 + ': True')
    Add-NewtonCheck $verdict 'dsrm_file' $dsrm ([string](Find-NewtonLine $Lines 'dsrm.bin deleted on ')) 'op_failed'
    $identity = Test-NewtonLineIs $Lines 'remote identity: ' ('remote identity: ' + [string]$Values['Netbios'] + '\' + [string]$Values['BuildUser'] + ' | auth Kerberos')
    Add-NewtonCheck $verdict 'remote_identity' $identity ([string](Find-NewtonLine $Lines 'remote identity: ')) 'op_failed'
    $status = $false
    $reboot = $false
    foreach ($line in $Lines) {
        if ([string]$line -cmatch '\AStatus\s+: Success\s*\z') { $status = $true }
        if ([string]$line -cmatch '\ARebootRequired\s+: True\s*\z') { $reboot = $true }
    }
    Add-NewtonCheck $verdict 'install' ($status -and $reboot) ('Status Success ' + [string]$status + ', RebootRequired ' + [string]$reboot) 'op_failed'
    $restart = Test-NewtonLineIs $Lines 'shutdown /r /t 10 on ' ('shutdown /r /t 10 on ' + $dc2 + ' exit 0')
    Add-NewtonCheck $verdict 'restart' $restart ([string](Find-NewtonLine $Lines 'shutdown /r /t 10 on ')) 'op_failed'
    $after = Find-NewtonLine $Lines 'after: '
    $afterOk = $false
    if (($null -ne $after) -and ([string]$after -cmatch '\Aafter: (.+) \| pwdLastSet [0-9]+ \| userAccountControl 532480 \| primaryGroupID 516\z')) {
        $afterOk = ($Matches[1]).Equals(('CN=' + $dc2 + ',OU=Domain Controllers,' + $dn), [System.StringComparison]::OrdinalIgnoreCase)
    }
    Add-NewtonCheck $verdict 'dc_after' $afterOk ([string]$after) 'readback_failed'
    $all = $true
    foreach ($check in $verdict['checks']) { if (-not [bool]$check['ok']) { $all = $false } }
    $verdict['checks'].Insert(0, [ordered]@{ name = 's7_install'; ok = $all; detail = 'Install-ADDSDomainController on ' + $dc2 })
    return $verdict
}

function ConvertTo-NewtonRepadminTime {
    # A time of repadmin /csv ('yyyy-MM-dd HH:mm:ss'), or $null.
    param([string]$Text)
    $at = [DateTime]::MinValue
    if ([DateTime]::TryParseExact($Text, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$at)) { return $at }
    return $null
}

function Test-NewtonOldReplicaFailure {
    # A row with a failure is accepted only when all three hold (the maintainer's
    # decision of 2026-11-21 on open point 77, refined): its last failure is
    # older than the read-back's start less 2 minutes, some row of the same
    # naming context, in either direction, shows 0 failures and a success
    # after it, and a LATER poll of the op confirmed the row unchanged
    # ('old failures confirmed: True' and at least two polls).  The schema
    # does not change, so nothing clears a failure DC2's boot left.
    # Without a start time, without a confirming later poll, or with a
    # failure inside the two minutes, nothing is accepted.
    # This sees the last poll's rows only: that a row seen clean and failing
    # again is never accepted (the maintainer, 2026-11-22) is the op's check: no poll
    # converges while that row fails.
    param($Row, $NcRows, $Cutoff, [bool]$Confirmed, [int]$Polls)
    if (($null -eq $Cutoff) -or (-not $Confirmed) -or ($Polls -lt 2)) { return $false }
    $failed = ConvertTo-NewtonRepadminTime ([string]$Row.lastfail)
    if (($null -eq $failed) -or ($failed -ge $Cutoff.AddMinutes(-2))) { return $false }
    foreach ($other in $NcRows) {
        if (([string]$other.failures -cne '0') -or ([string]$other.status -cne '0')) { continue }
        $success = ConvertTo-NewtonRepadminTime ([string]$other.lastsuccess)
        if (($null -ne $success) -and ($success -gt $failed)) { return $true }
    }
    return $false
}

function Get-NewtonReplicaRowsOk {
    # The rows of repadmin /showrepl * /csv: every naming context of the
    # forest root replicated both ways, DC1 from DC2 and DC2 from DC1, with
    # 0 failures (or an old failure that a later success of the same
    # naming context outdates and a later poll confirmed unchanged), and no
    # error row.
    param([string[]]$Rows, [string]$Dc1, [string]$Dc2, [string]$Dn, $Cutoff = $null, [bool]$Confirmed = $false, [int]$Polls = 0)
    $ncs = @($Dn, ('CN=Configuration,' + $Dn), ('CN=Schema,CN=Configuration,' + $Dn), ('DC=DomainDnsZones,' + $Dn), ('DC=ForestDnsZones,' + $Dn))
    foreach ($row in $Rows) { if ($row.StartsWith('showrepl_ERROR', [System.StringComparison]::Ordinal)) { return 'an error row' } }
    $header = 'kind', 'dsite', 'dest', 'nc', 'ssite', 'src', 'transport', 'failures', 'lastfail', 'lastsuccess', 'status'
    $info = @($Rows | Where-Object { $_.StartsWith('showrepl_INFO,', [System.StringComparison]::Ordinal) })
    $data = @($info | ConvertFrom-Csv -Header $header)
    foreach ($pair in @(@($Dc1, $Dc2), @($Dc2, $Dc1))) {
        $mine = @($data | Where-Object { ([string]$_.dest).Equals($pair[0], [System.StringComparison]::OrdinalIgnoreCase) -and
            ([string]$_.src).Equals($pair[1], [System.StringComparison]::OrdinalIgnoreCase) })
        if ($mine.Count -ne $ncs.Count) { return ([string]$mine.Count + ' rows ' + $pair[0] + ' from ' + $pair[1]) }
        foreach ($nc in $ncs) {
            $row = @($mine | Where-Object { ([string]$_.nc).Equals($nc, [System.StringComparison]::OrdinalIgnoreCase) })
            if ($row.Count -ne 1) { return ('no row of ' + $nc + ' ' + $pair[0] + ' from ' + $pair[1]) }
            if (([string]$row[0].failures -cne '0') -or ([string]$row[0].status -cne '0')) {
                $sameNc = @($data | Where-Object { ([string]$_.nc).Equals($nc, [System.StringComparison]::OrdinalIgnoreCase) })
                if (-not (Test-NewtonOldReplicaFailure -Row $row[0] -NcRows $sameNc -Cutoff $Cutoff -Confirmed $Confirmed -Polls $Polls)) {
                    return ($nc + ' ' + $pair[0] + ' from ' + $pair[1] + ': failures ' + $row[0].failures + ', status ' + $row[0].status)
                }
            }
        }
    }
    return ''
}

function Get-NewtonReplicaFailingRows {
    # The rows of repadmin /showrepl * /csv that hold a failure (a failure
    # count or a status other than 0): the naming contexts of the forest
    # root, both ways.  DC2's own read needs to know whether the rows of
    # its last poll hold a failing row at all (the old-row rule of
    # 2026-11-24: a failed Replications test is accepted only on a pass
    # that holds one).
    param([string[]]$Rows, [string]$Dc1, [string]$Dc2, [string]$Dn)
    $ncs = @($Dn, ('CN=Configuration,' + $Dn), ('CN=Schema,CN=Configuration,' + $Dn), ('DC=DomainDnsZones,' + $Dn), ('DC=ForestDnsZones,' + $Dn))
    $header = 'kind', 'dsite', 'dest', 'nc', 'ssite', 'src', 'transport', 'failures', 'lastfail', 'lastsuccess', 'status'
    $info = @($Rows | Where-Object { $_.StartsWith('showrepl_INFO,', [System.StringComparison]::Ordinal) })
    $data = @($info | ConvertFrom-Csv -Header $header)
    $failing = 0
    foreach ($pair in @(@($Dc1, $Dc2), @($Dc2, $Dc1))) {
        $mine = @($data | Where-Object { ([string]$_.dest).Equals($pair[0], [System.StringComparison]::OrdinalIgnoreCase) -and
            ([string]$_.src).Equals($pair[1], [System.StringComparison]::OrdinalIgnoreCase) })
        foreach ($nc in $ncs) {
            $row = @($mine | Where-Object { ([string]$_.nc).Equals($nc, [System.StringComparison]::OrdinalIgnoreCase) })
            if ($row.Count -ne 1) { continue }
            if (([string]$row[0].failures -cne '0') -or ([string]$row[0].status -cne '0')) { $failing = $failing + 1 }
        }
    }
    return $failing
}

function Get-NewtonBlockLines {
    # The lines a header line of the read-back says follow it ('..., N
    # lines:'), each indented two spaces, without the indent: $null when
    # the header is missing or the block is short.
    param($Lines, [string]$HeaderPattern)
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ([string]$Lines[$i] -cmatch $HeaderPattern) {
            $count = [int]$Matches['n']
            $out = New-Object System.Collections.ArrayList
            for ($j = 1; $j -le $count; $j++) {
                if (($i + $j) -ge $Lines.Count) { return $null }
                $one = [string]$Lines[$i + $j]
                if (-not $one.StartsWith('  ', [System.StringComparison]::Ordinal)) { return $null }
                [void]$out.Add($one.Substring(2))
            }
            return ,([string[]]$out.ToArray())
        }
    }
    return $null
}

function Get-NewtonStage7ReadVerdict {
    # The read-back block of s7-read (the maintainer's decision K17): repadmin 0
    # failures both ways (an old failure with a later success of its naming
    # context, older than the read-back's start less 2 minutes and confirmed
    # unchanged by a later poll, passes; no poll converges while a row seen
    # clean fails again), dcdiag on DC1 (exit 0, every test
    # of the list passed by that DC, none failed but the accepted pair), the
    # poll converged.  DC2's genid and dcdiag are DC2's own (s7-dc; open
    # point 77).
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $dn = Get-NewtonDomainDn ([string]$Values['DnsName'])
    $dc1 = [string]$Values['Dc1Host']
    $dc2 = [string]$Values['Dc2Host']
    $start = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) { if ([string]$Lines[$i] -cmatch '\Aread-back after [0-9]+ s, [0-9]+ polls, converged (True|False)\z') { $start = $i } }
    if ($start -lt 0) {
        Add-NewtonCheck $verdict 's7_read' $false 'the read-back block is missing' 'readback_failed'
        return $verdict
    }
    $block = @($Lines[$start..($Lines.Count - 1)])
    $rows = Get-NewtonBlockLines $block '\Arepadmin /showrepl \* /csv exit 0, (?<n>[0-9]+) lines:\z'
    $replication = 'the repadmin read is missing or did not exit 0'
    $cutoff = $null
    $polls = 0
    if ([string]$Lines[$start] -cmatch '\Aread-back after [0-9]+ s, (?<p>[0-9]+) polls, converged (True|False)\z') { $polls = [int]$Matches['p'] }
    $startedLine = Find-NewtonLine $block 'read-back started: '
    if (($null -ne $startedLine) -and ([string]$startedLine -cmatch '\Aread-back started: (?<t>[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\z')) {
        $cutoff = ConvertTo-NewtonRepadminTime $Matches['t']
    }
    $confirmed = ([string](Find-NewtonLine $block 'old failures confirmed: ') -ceq 'old failures confirmed: True')
    if ($null -ne $rows) { $replication = Get-NewtonReplicaRowsOk -Rows $rows -Dc1 $dc1 -Dc2 $dc2 -Dn $dn -Cutoff $cutoff -Confirmed $confirmed -Polls $polls }
    Add-NewtonCheck $verdict 'replication' ($replication -ceq '') ('0 failures both ways' + $(if ($replication) { ': not so, ' + $replication } else { '' })) 'readback_failed'
    # dcdiag on DC1, the full form: it exited 0 and its test lines show
    # every test of the list passed by that DC (X3 of the review of
    # f4cebe6).  The block's own variable is not $lines: PowerShell names
    # are case-insensitive, and $Lines is the op's output (T1).
    foreach ($one in @(,@('dcdiag_dc1', '\Adcdiag exit 0, (?<n>[0-9]+) lines:\z', $dc1, 'dcdiag '))) {
        $diagLines = Get-NewtonBlockLines $block $one[1]
        if ($null -eq $diagLines) {
            Add-NewtonCheck $verdict $one[0] $false ('no dcdiag block that exited 0 and holds the lines it counts: ' + [string](Find-NewtonLine $block $one[3])) 'readback_failed'
            continue
        }
        $diag = Get-NewtonDcdiagServerCheck -Lines $diagLines -Server $one[2]
        Add-NewtonCheck $verdict $one[0] ([bool]$diag['ok']) ([string]$diag['detail']) 'readback_failed'
    }
    # The op's own poll said it converged; a read-back that ran out its
    # wait is not one, whatever its last rows say.
    $converged = ([string]$Lines[$start]).EndsWith(', converged True', [System.StringComparison]::Ordinal)
    Add-NewtonCheck $verdict 'converged' $converged ([string]$Lines[$start]) 'readback_failed'
    $all = $true
    foreach ($check in $verdict['checks']) { if (-not [bool]$check['ok']) { $all = $false } }
    $verdict['checks'].Insert(0, [ordered]@{ name = 's7_read'; ok = $all; detail = [string]$Lines[$start] })
    return $verdict
}

function Get-NewtonStage7JoinVerdict {
    # djoin /requestODJ on DC2 with DC1 as its DNS server; the blob gone.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $dns = [string]$Values['DnsName']
    $dc1Ip = [string]$Values['Dc1Ip']
    $dnsOk = (Test-NewtonLineIs $Lines 'dns client: ' ('dns client: ' + $dc1Ip)) -and
        (Test-NewtonLineIs $Lines ('resolve ' + $dns + ': ') ('resolve ' + $dns + ': ' + $dc1Ip)) -and
        (Test-NewtonLineIs $Lines 'srv: ' ('srv: ' + [string]$Values['Dc1Host'] + '.' + $dns))
    Add-NewtonCheck $verdict 'dns' $dnsOk ([string](Find-NewtonLine $Lines 'srv: ')) 'op_failed'
    $exit = Find-NewtonLine $Lines 'djoin /requestODJ exit '
    $ran = ($null -ne $exit) -and ([string]$exit -cmatch '\Adjoin /requestODJ exit 0 in [0-9]+ s, [0-9]+ lines:\z')
    $done = $null -ne (Find-NewtonLine $Lines '  [The provisioning request completed successfully.]')
    Add-NewtonCheck $verdict 'djoin_request' ($ran -and $done) ([string]$exit) 'op_failed'
    $gone = Test-NewtonLineIs $Lines 'blob deleted: ' 'blob deleted: True'
    Add-NewtonCheck $verdict 'blob_deleted' $gone ([string](Find-NewtonLine $Lines 'blob deleted: ')) 'op_failed'
    $cs = Test-NewtonLineIs $Lines 'cs before the reboot: ' ('cs before the reboot: Name ' + [string]$Values['Dc2Host'] + ' | DomainRole 2 | PartOfDomain False | Domain WORKGROUP')
    Add-NewtonCheck $verdict 'workgroup_before' $cs ([string](Find-NewtonLine $Lines 'cs before the reboot: ')) 'readback_failed'
    $all = $true
    foreach ($check in $verdict['checks']) { if (-not [bool]$check['ok']) { $all = $false } }
    $verdict['checks'].Insert(0, [ordered]@{ name = 's7_join'; ok = $all; detail = 'djoin /requestODJ' })
    return $verdict
}

function Get-NewtonStage7MemberVerdict {
    # DC2 after the join's boot: a member of the plan's domain.
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $ok = Test-NewtonLineIs $Lines 'cs: ' ('cs: Name ' + [string]$Values['Dc2Host'] + ' | DomainRole 3 | PartOfDomain True | Domain ' + [string]$Values['DnsName'])
    Add-NewtonCheck $verdict 's7_member' $ok ([string](Find-NewtonLine $Lines 'cs: ')) 'readback_failed'
    return $verdict
}

function Get-NewtonStage7DcVerdict {
    # DC2 after the promotion's boot: a DC (DomainRole 4) with
    # msDS-GenerationId on its computer object; its machine password, the
    # one the blob carried, rotated: pwdLastSet advanced, to a time after
    # this boot; the secure channel holds (the maintainer's decision K16).
    # Its own dcdiag may fail the Replications test only under the
    # maintainer's old-row rule of 2026-11-23 (the same rule the s7-read
    # parser applies to the rows of repadmin /showrepl * /csv).
    param($Lines, $Values)
    $verdict = New-NewtonVerdict
    $dn = Get-NewtonDomainDn ([string]$Values['DnsName'])
    $dc1 = [string]$Values['Dc1Host']
    $dc2 = [string]$Values['Dc2Host']
    $role = Test-NewtonLineIs $Lines 'cs: ' ('cs: Name ' + $dc2 + ' | DomainRole 4 | PartOfDomain True | Domain ' + [string]$Values['DnsName'])
    Add-NewtonCheck $verdict 's7_dc' $role ([string](Find-NewtonLine $Lines 'cs: ')) 'readback_failed'
    $genid = Find-NewtonLine $Lines 'msDS-GenerationId on '
    $genidOk = $false
    if (($null -ne $genid) -and ([string]$genid -cmatch '\AmsDS-GenerationId on (.+): present, 8 bytes, [0-9a-f]{16}\z')) {
        $genidOk = ($Matches[1]).Equals(('CN=' + $dc2 + ',OU=Domain Controllers,' + $dn), [System.StringComparison]::OrdinalIgnoreCase)
    }
    Add-NewtonCheck $verdict 'generation_id' $genidOk ([string]$genid) 'readback_failed'
    $before = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'pwdLastSet before the reset: ') 'pwdLastSet before the reset: '
    $after = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'pwdLastSet after the reset: ') 'pwdLastSet after the reset: '
    $boot = Get-NewtonAfterPrefix (Find-NewtonLine $Lines 'LastBootUpTime: ') 'LastBootUpTime: '
    $rotated = $false
    $detail = 'before ' + [string]$before + ', after ' + [string]$after + ', boot ' + [string]$boot
    if (($null -ne $before) -and ($null -ne $after) -and ($null -ne $boot) -and
        ([string]$before -cmatch '\A[0-9]{1,19}\z') -and ([string]$after -cmatch '\A([0-9]{1,19}) \| ')) {
        $afterValue = [int64]$Matches[1]
        $bootTime = [DateTime]::MinValue
        $parsed = [DateTime]::TryParse([string]$boot, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind, [ref]$bootTime)
        if ($parsed -and ($afterValue -gt [int64]$before) -and ($afterValue -gt 0)) {
            $rotated = ([DateTime]::FromFileTimeUtc($afterValue) -ge $bootTime.ToUniversalTime())
        }
    }
    Add-NewtonCheck $verdict 'machine_password' $rotated $detail 'readback_failed'
    # The secure channel holds: nltest /sc_verify exited 0, and inside the
    # block its header counts it says the connection and the verification
    # both answered NERR_Success and the command completed (F3 of the
    # review; constructed, open point 53).  A
    # Test-ComputerSecureChannel line is never read: on a DC the cmdlet
    # gives false errors (Microsoft's reference).
    $nl = Get-NewtonBlockLines $Lines '\Anltest /sc_verify exit 0, (?<n>[0-9]+) lines:\z'
    $channel = ($null -ne $nl) -and
        (@($nl | Where-Object { $_.TrimEnd() -ceq 'Trusted DC Connection Status Status = 0 0x0 NERR_Success' }).Count -eq 1) -and
        (@($nl | Where-Object { $_.TrimEnd() -ceq 'Trust Verification Status = 0 0x0 NERR_Success' }).Count -eq 1) -and
        (@($nl | Where-Object { $_.TrimEnd() -ceq 'The command completed successfully' }).Count -eq 1)
    Add-NewtonCheck $verdict 'secure_channel' $channel ([string](Find-NewtonLine $Lines 'nltest /sc_verify exit ')) 'readback_failed'
    # dcdiag on DC2 itself (open point 77): exit 0, every test of the list
    # passed by DC2, none failed but the accepted pair.  The Replications
    # test may fail as well, but only under the maintainer's old-row rule
    # of 2026-11-23: the rows of the last poll of repadmin /showrepl * /csv
    # pass the same rule the s7-read parser applies (the failure is older
    # than the read's start less two minutes, a row of the same naming
    # context in either direction shows 0 failures and a success after it),
    # an old failure was confirmed by a later poll, and the read's start
    # line is there.  A line that is missing means the failure is not
    # accepted.
    # The rule of 2026-11-24 as well: the last poll's rows hold at least
    # one failing row (every one of them passing the rule above).  Rows
    # that are all clean hold no old failure at all, so a failed
    # Replications then failed for another reason and is not accepted.
    $dc2Diag = Get-NewtonBlockLines $Lines '\Adcdiag exit 0, (?<n>[0-9]+) lines:\z'
    if ($null -eq $dc2Diag) {
        Add-NewtonCheck $verdict 'dcdiag_dc2' $false ('no dcdiag block that exited 0 and holds the lines it counts: ' + [string](Find-NewtonLine $Lines 'dcdiag exit ')) 'readback_failed'
    } else {
        $oldRows = $false
        $rows = Get-NewtonBlockLines $Lines '\Arepadmin /showrepl \* /csv exit 0, (?<n>[0-9]+) lines:\z'
        $cutoff = $null
        $started = Find-NewtonLine $Lines 'read-back started: '
        if (($null -ne $started) -and ([string]$started -cmatch '\Aread-back started: (?<t>[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\z')) {
            $cutoff = ConvertTo-NewtonRepadminTime $Matches['t']
        }
        $confirmed = ([string](Find-NewtonLine $Lines 'old failures confirmed: ') -ceq 'old failures confirmed: True')
        $polls = 0
        $converged = $false
        foreach ($line in $Lines) {
            if ([string]$line -cmatch '\Aread-back after [0-9]+ s, (?<p>[0-9]+) polls, converged (True|False)\z') {
                $polls = [int]$Matches['p']
                $converged = ($Matches[1] -ceq 'True')
            }
        }
        if ($null -ne $rows) {
            $replication = Get-NewtonReplicaRowsOk -Rows $rows -Dc1 $dc1 -Dc2 $dc2 -Dn $dn `
                -Cutoff $cutoff -Confirmed $confirmed -Polls $polls
            # The rule of 2026-11-24: the last poll's rows hold at least one
            # failing row (every one of them passing the rule above).
            $failing = Get-NewtonReplicaFailingRows -Rows $rows -Dc1 $dc1 -Dc2 $dc2 -Dn $dn
            # The op's own poll says it converged: a read that ran out its
            # wait is not one, whatever its last rows say (the s7-read
            # parser reads the same line).
            $oldRows = ($replication -ceq '') -and $confirmed -and ($polls -ge 2) -and `
                ($null -ne $cutoff) -and $converged -and ($failing -ge 1)
        }
        $diag = Get-NewtonDcdiagServerCheck -Lines $dc2Diag -Server $dc2 -AcceptOldReplications:$oldRows
        Add-NewtonCheck $verdict 'dcdiag_dc2' ([bool]$diag['ok']) ([string]$diag['detail']) 'readback_failed'
    }
    return $verdict
}

function Get-NewtonOpVerdict {
    # The verdict of one op's output: the parser of that op.
    param([string]$Op, [string]$Output, $Values, [int64]$Now, [int64]$NotBefore, $Groups, [int]$Result = 0)
    $lines = Get-NewtonOutputLines $Output
    if (Test-NewtonOpFailed -Result $Result -Lines $lines) {
        $verdict = New-NewtonVerdict
        $fail = Find-NewtonLine $lines 'FAIL: '
        # The read of stage 4's groups failed: a read that fails stops
        # readback_failed, never passes (the maintainer's decision, 2026-11-13).
        # So do the reads of a resumed stage 3 and of stage 6 (IC2 of the
        # task 6 triage): a read that fails is a read-back that failed.
        $failCode = 'op_failed'
        if (@('s3-state', 's4-groups', 's4-state', 's6-read', 's7-read', 's7-member', 's7-dc', 's8-read') -ccontains $Op) { $failCode = 'readback_failed' }
        # s5-structure found an owner admin account Newton did not make
        # (IC4): it stopped before any write to it, on what it read.
        $foreign = $null
        if ($Op -ceq 's5-structure') { $foreign = Find-NewtonLine $lines 'owner admin present, not made by this build: ' }
        if ($null -ne $foreign) { $failCode = 'readback_failed' }
        Add-NewtonCheck $verdict $Op $false ('exit ' + [string]$Result + ' | ' + [string]$fail) $failCode
        if ($null -ne $foreign) { Add-NewtonCheck $verdict 'owner_admin' $false ([string]$foreign) 'readback_failed' }
        if ($Op -ceq 's4-groups') { Add-NewtonCheck $verdict 'directory_groups' $false 'the directory read of the groups failed' 'readback_failed' }
        return $verdict
    }
    switch ($Op) {
        's0-read' { return (Get-NewtonStage0Verdict -Lines $lines -Values $Values -Now $Now -NotBefore $NotBefore) }
        's1-base' { return (Get-NewtonStage1BaseVerdict -Lines $lines -Values $Values) }
        's1-read' { return (Get-NewtonStage1ReadVerdict -Lines $lines -Values $Values) }
        's2-role' { return (Get-NewtonRoleVerdict -Lines $lines -Values $Values) }
        's2-promote' { return (Get-NewtonPromoteVerdict -Lines $lines) }
        's2-groups' { return (Get-NewtonGroupsVerdict -Lines $lines -Values $Values) }
        's2-read' { return (Get-NewtonStage2ReadVerdict -Lines $lines -Values $Values -Groups $Groups) }
        's3-recyclebin' { return (Get-NewtonStage3Verdict -Lines $lines -Values $Values) }
        's3-state' { return (Get-NewtonStage3StateVerdict -Lines $lines -Values $Values) }
        's4-laps' { return (Get-NewtonStage4Verdict -Lines $lines -Values $Values) }
        's4-groups' { return (Get-NewtonStage4GroupsVerdict -Lines $lines -Values $Values -Groups $Groups) }
        's4-state' { return (Get-NewtonStage4StateVerdict -Lines $lines -Values $Values) }
        's5-structure' { return (Get-NewtonStage5Verdict -Lines $lines -Values $Values) }
        's6-gpo-domain' { return (Get-NewtonStage6GpoVerdict -Lines $lines -Values $Values -Gpo 'domain') }
        's6-gpo-dc' { return (Get-NewtonStage6GpoVerdict -Lines $lines -Values $Values -Gpo 'dc') }
        's6-read' { return (Get-NewtonStage6ReadVerdict -Lines $lines -Values $Values) }
        's7-provision' { return (Get-NewtonStage7ProvisionVerdict -Lines $lines -Values $Values) }
        's7-install' { return (Get-NewtonStage7InstallVerdict -Lines $lines -Values $Values) }
        's7-read' { return (Get-NewtonStage7ReadVerdict -Lines $lines -Values $Values) }
        's7-join' { return (Get-NewtonStage7JoinVerdict -Lines $lines -Values $Values) }
        's7-member' { return (Get-NewtonStage7MemberVerdict -Lines $lines -Values $Values) }
        's7-dc' { return (Get-NewtonStage7DcVerdict -Lines $lines -Values $Values) }
        's8-audit' { return (Get-NewtonStage8SetupVerdict -Op $Op -Lines $lines -Values $Values) }
        's8-ops' { return (Get-NewtonStage8SetupVerdict -Op $Op -Lines $lines -Values $Values) }
        's8-restart' { return (Get-NewtonStage8RestartVerdict -Lines $lines -Values $Values) }
        's8-read' { return (Get-NewtonStage8ReadVerdict -Lines $lines -Values $Values) }
        's9-da' { return (Get-NewtonStage9DaVerdict -Lines $lines) }
        's9-register' { return (Get-NewtonStage9RegisterVerdict -Lines $lines -Values $Values) }
    }
    Throw-NewtonRefusal 'schema' 'the op has no parser'
}

# ---------------------------------------------------------------------------
# the Windows side: the only functions that touch the server.  The tests
# replace these and nothing else.
# ---------------------------------------------------------------------------

function Test-NewtonWindowsHost {
    # The templates run only under Windows.
    return ($env:OS -eq 'Windows_NT')
}

function Get-NewtonSessionUser {
    # The account of the helper's session, as the password task names it:
    # BUILD1\newton-build before the promotion, NBUILD\newton-build after.
    return [Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Get-NewtonBuildPassword {
    # The password of the build account, out of pw.bin (DPAPI
    # LocalMachine; MEASURED-1.5, "Set-up").
    Add-Type -AssemblyName System.Security
    $protected = [System.IO.File]::ReadAllBytes($script:BuildDir + '\pw.bin')
    return [Text.Encoding]::UTF8.GetString(
        [Security.Cryptography.ProtectedData]::Unprotect($protected, $null, 'LocalMachine'))
}

function Get-NewtonClockSeconds {
    # A monotonic clock, in seconds, for the waits of the password task.
    return ([Diagnostics.Stopwatch]::GetTimestamp() / [double][Diagnostics.Stopwatch]::Frequency)
}

function Invoke-NewtonScheduledTask {
    # The task runner of both the password task and the SYSTEM task:
    # register the task, start it, wait for it, read its outcome and
    # unregister it.  The password task registers the build account with
    # the password of pw.bin; the SYSTEM task registers NT AUTHORITY\SYSTEM
    # with a principal and with no password at all (the maintainer's
    # ruling, 2026-11-23).  Everything else is the same: the outcomes,
    # the files, the give-up, the unregister.
    #
    # The answer is {outcome, result, found}:
    #   ended: the task ran and ended; result is its LastTaskResult, a
    #     UInt32 read as the signed HRESULT it is.
    #   not_started: the task did not leave 267011 (has not run yet)
    #     within TaskStartSeconds (or WaitSeconds, when that is less).
    #     It is disabled, read again, and only then unregistered, and
    #     found says what the two reads saw: nothing ran.
    #   running: the task still runs at WaitSeconds.  It is not stopped
    #     (an op of an irreversible stage killed half way is worse than
    #     one that finishes) and not unregistered: the op writes its own
    #     result file, and a status request turns that file into the
    #     terminal entry of the stage.
    # A task of the same name that still runs, from an earlier request,
    # is neither replaced nor unregistered.
    param([string]$Op, [string]$OpPath, [int]$WaitSeconds = $script:TaskWaitSeconds, [switch]$AsSystem)
    if ($WaitSeconds -lt 0) { $WaitSeconds = 0 }
    $startSeconds = [Math]::Min($script:TaskStartSeconds, $WaitSeconds)
    $name = 'NewtonBuild-' + $Op
    $existing = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        if ([string]$existing.State -eq 'Running') {
            throw ('the task ' + $name + ' of an earlier request is still running')
        }
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + $OpPath)
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 60)
    if ($AsSystem) {
        # The machine account of the server: no password, and none of the
        # network credentials of the build account (the maintainer's
        # ruling, 2026-11-23).
        $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
            -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $name -Action $action -Settings $settings `
            -Principal $principal | Out-Null
    } else {
        $user = Get-NewtonSessionUser
        $password = Get-NewtonBuildPassword
        try {
            Register-ScheduledTask -TaskName $name -Action $action -Settings $settings -User $user `
                -Password $password -RunLevel Highest | Out-Null
        } finally {
            $password = $null
        }
    }
    $outcome = 'ended'
    $result = [int64]-1
    $found = ''
    $unregister = $true
    try {
        Start-ScheduledTask -TaskName $name
        $started = Get-NewtonClockSeconds
        $state = ''
        $info = $null
        $began = $false
        do {
            Start-Sleep -Seconds 2
            $info = Get-ScheduledTaskInfo -TaskName $name
            $state = [string](Get-ScheduledTask -TaskName $name).State
            $began = ($state -eq 'Running') -or ([int64]$info.LastTaskResult -ne $script:TaskNotRunResult)
        } while ((-not $began) -and (((Get-NewtonClockSeconds) - $started) -lt $startSeconds))
        if (-not $began) {
            # The give-up.  The task may start between the last read and
            # the unregister: disabled, it cannot start any more, so the
            # read after it is the last word on whether the op ran.
            $null = Disable-ScheduledTask -TaskName $name -ErrorAction Stop
            $info = Get-ScheduledTaskInfo -TaskName $name
            $state = [string](Get-ScheduledTask -TaskName $name).State
            $began = ($state -eq 'Running') -or ([int64]$info.LastTaskResult -ne $script:TaskNotRunResult)
            $found = 'disabled, State ' + $state + ', LastTaskResult ' + [string]$info.LastTaskResult
        }
        if (-not $began) {
            $outcome = 'not_started'
        } else {
            while (($state -eq 'Running') -and
                (((Get-NewtonClockSeconds) - $started) -lt $WaitSeconds)) {
                Start-Sleep -Seconds 2
                $info = Get-ScheduledTaskInfo -TaskName $name
                $state = [string](Get-ScheduledTask -TaskName $name).State
            }
            if ($state -eq 'Running') {
                $outcome = 'running'
                $unregister = $false
            } else {
                # The state and the result are two reads: a task that
                # ends between them reads Ready with LastTaskResult still
                # 267009 (SCHED_S_TASK_RUNNING; measured, lab run 7,
                # 2026-11-24: s7-provision ended 0 in 3 s and was reported
                # 267009).  The result is read again until it settles,
                # for at most TaskResultSettleSeconds; one that never
                # settles stays 267009, a failure.
                $settle = Get-NewtonClockSeconds
                $info = Get-ScheduledTaskInfo -TaskName $name
                while (([int64]$info.LastTaskResult -eq $script:TaskRunningResult) -and
                    (((Get-NewtonClockSeconds) - $settle) -lt $script:TaskResultSettleSeconds)) {
                    Start-Sleep -Seconds 1
                    $info = Get-ScheduledTaskInfo -TaskName $name
                }
                $result = [int64]$info.LastTaskResult
                if ($result -gt [int]::MaxValue) { $result = $result - 4294967296 }
            }
        }
    } finally {
        if ($unregister) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    if ($outcome -eq 'not_started') {
        # What is left after the unregister, reported with the stop.
        $left = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($null -eq $left) {
            $found = $found + '; after the unregister: no task'
        } else {
            $found = $found + '; after the unregister: the task is still registered, State ' + [string]$left.State
        }
    } elseif ($outcome -eq 'running') {
        $found = 'still running after ' + [string]$WaitSeconds + ' s; it is left to finish'
    }
    return [ordered]@{ outcome = $outcome; result = [int]$result; found = $found }
}

function Invoke-NewtonPasswordTask {
    # One op in a one-shot task registered with the password of the
    # build account from pw.bin (MEASURED-1.5, "Set-up").  The password
    # is a cmdlet parameter in this process, never on a command line.
    #
    # The answer is {outcome, result, found}: the one of
    # Invoke-NewtonScheduledTask.
    param([string]$Op, [string]$OpPath, [int]$WaitSeconds = $script:TaskWaitSeconds)
    return (Invoke-NewtonScheduledTask -Op $Op -OpPath $OpPath -WaitSeconds $WaitSeconds)
}

function Invoke-NewtonSystemTask {
    # One op in a one-shot task registered as NT AUTHORITY\SYSTEM, the
    # machine account of the server, with no password (the maintainer's
    # ruling, 2026-11-23: DC2's own read runs as SYSTEM, because the
    # helper's key login holds no network credentials and dcdiag's
    # KnowsOfRoleHolders and RidManager fail under it).
    #
    # The answer is {outcome, result, found}: the one of
    # Invoke-NewtonScheduledTask.
    param([string]$Op, [string]$OpPath, [int]$WaitSeconds = $script:TaskWaitSeconds)
    return (Invoke-NewtonScheduledTask -Op $Op -OpPath $OpPath -WaitSeconds $WaitSeconds -AsSystem)
}

function Invoke-NewtonStageOp {
    # One op: write it, run it (in this session, in the password task or
    # in the SYSTEM task) and read the output it wrote.  The answer is
    # {outcome, result, output}; the outcome is the one of
    # Invoke-NewtonPasswordTask, and ended for an op of this session.
    param([string]$Op, [string]$Script, [bool]$AsTask, [int]$WaitSeconds = $script:TaskWaitSeconds, [switch]$AsSystem)
    foreach ($directory in @(($script:BuildDir + '\ops'), ($script:BuildDir + '\out'))) {
        if (-not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Path $directory -Force }
    }
    $opPath = Get-NewtonOpPath $Op
    $outPath = Get-NewtonOutPath $Op
    [System.IO.File]::WriteAllText($opPath, $Script, (New-Object System.Text.UTF8Encoding $true))
    Clear-NewtonOpResult -Op $Op
    $outcome = 'ended'
    $result = -1
    $found = ''
    if ($AsTask) {
        if ($AsSystem) {
            $task = Invoke-NewtonSystemTask -Op $Op -OpPath $opPath -WaitSeconds $WaitSeconds
        } else {
            $task = Invoke-NewtonPasswordTask -Op $Op -OpPath $opPath -WaitSeconds $WaitSeconds
        }
        $outcome = [string]$task['outcome']
        $result = [int]$task['result']
        $found = [string]$task['found']
    } else {
        $null = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $opPath
        $result = [int]$LASTEXITCODE
    }
    # A task still running holds its output file open, so it is not read
    # (MEASURED-1.5 "Stage 8 on BUILD1, 2026-11-18": s7-read outlived its
    # wait); a later status reads it from the result file.
    $output = ''
    if (($outcome -cne 'running') -and (Test-Path -LiteralPath $outPath)) { $output = [System.IO.File]::ReadAllText($outPath) }
    return @{ outcome = $outcome; result = $result; output = $output; found = $found }
}

function Clear-NewtonOpResult {
    # The output and the result file of an earlier run of an op: gone
    # before the op runs, so neither is read as the outcome of this run.
    param([string]$Op)
    foreach ($path in @((Get-NewtonOutPath $Op), (Get-NewtonResultPath $Op))) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
}

function Read-NewtonOpResult {
    # The result file an op wrote as its last act, and its output: $null
    # when there is no result file (the op did not run to its end).
    param([string]$Op)
    $resultPath = Get-NewtonResultPath $Op
    if (-not (Test-Path -LiteralPath $resultPath)) { return $null }
    $text = ([System.IO.File]::ReadAllText($resultPath)).Trim()
    $result = -1
    if ($text -cmatch '\A-?[0-9]{1,9}\z') { $result = [int]$text }
    $output = ''
    $outPath = Get-NewtonOutPath $Op
    if (Test-Path -LiteralPath $outPath) { $output = [System.IO.File]::ReadAllText($outPath) }
    return @{ result = $result; output = $output }
}

function Test-NewtonPasswordTaskRunning {
    # True when the task of an op is running, or queued to run: the
    # password task of the op, or its SYSTEM task (the name of the task is
    # the same for both).
    param([string]$Op)
    $task = Get-ScheduledTask -TaskName ('NewtonBuild-' + $Op) -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $false }
    return (@('Running', 'Queued') -contains [string]$task.State)
}

function Remove-NewtonPasswordTask {
    # The task of an op that is no longer running, left behind by a
    # helper that did not reach its own Unregister-ScheduledTask (the
    # password task of the op, or its SYSTEM task).
    param([string]$Op)
    Unregister-ScheduledTask -TaskName ('NewtonBuild-' + $Op) -Confirm:$false -ErrorAction SilentlyContinue
}

function Invoke-NewtonRestart {
    # The restart of a stage.  It is delayed so the answer of the helper
    # reaches Newton first; the rebooting entry is on the disk already.
    # True when shutdown.exe accepted the restart.
    $null = & shutdown.exe /r /t 10
    return ($LASTEXITCODE -eq 0)
}

function Wait-NewtonDirectory {
    # After a boot the directory is ready when Get-ADDomain answers, not
    # when ADWS says Running (MEASURED-1.5, section 3 and stage 2).  The
    # module's import is retried with it: right after a boot the import
    # fails mounting its AD: drive ("InitializeDefaultDrives ... failed";
    # MEASURED-1.5 "Stage 8 on BUILD1, 2026-11-18").
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $script:DirectoryWaitSeconds) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue
            $null = Get-ADDomain -ErrorAction Stop
            return $true
        } catch {
            Start-Sleep -Seconds 3
        }
    }
    return $false
}

function Get-NewtonOwnGroups {
    # The groups of this session's own token: the build login is the
    # S4U token the design reads the memberships in.
    return @(& whoami.exe /groups /fo csv /nh)
}

function Write-NewtonSecretFile {
    # The DSRM secret to a DPAPI LocalMachine file for the task; the op
    # deletes it.  The secret is never on a command line or in a script.
    param([string]$Path, [string]$Secret)
    Add-Type -AssemblyName System.Security
    $bytes = [Text.Encoding]::UTF8.GetBytes($Secret)
    try {
        $protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'LocalMachine')
        [System.IO.File]::WriteAllBytes($Path, $protected)
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Remove-NewtonSecretFile {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
}

# ---------------------------------------------------------------------------
# the secret of the plan (plan.derive_secret)
# ---------------------------------------------------------------------------

function Get-NewtonHmac {
    param([byte[]]$Key, [byte[]]$Data)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (, $Key)
    try { return ,$hmac.ComputeHash($Data) } finally { $hmac.Dispose() }
}

function Get-NewtonDerivedSecret {
    # HKDF-SHA256(K, salt = the plan digest, info), encoded to the
    # complexity rules exactly as plan._encode_secret does.
    param([byte[]]$Key, [string]$Digest, [string]$Info)
    $prk = Get-NewtonHmac -Key ([Text.Encoding]::ASCII.GetBytes($Digest)) -Data $Key
    $infoBytes = [Text.Encoding]::ASCII.GetBytes($Info)
    $okm = New-Object System.Collections.Generic.List[byte]
    $block = [byte[]]@()
    $counter = 1
    while ($okm.Count -lt $script:SecretLength) {
        $message = New-Object System.Collections.Generic.List[byte]
        $message.AddRange([byte[]]$block)
        $message.AddRange($infoBytes)
        $message.Add([byte]$counter)
        $block = Get-NewtonHmac -Key $prk -Data $message.ToArray()
        $okm.AddRange([byte[]]$block)
        $counter = $counter + 1
    }
    $alphabet = $script:SecretUpper + $script:SecretLower + $script:SecretDigit + $script:SecretSymbol
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append($script:SecretUpper[$okm[0] % $script:SecretUpper.Length])
    [void]$builder.Append($script:SecretLower[$okm[1] % $script:SecretLower.Length])
    [void]$builder.Append($script:SecretDigit[$okm[2] % $script:SecretDigit.Length])
    [void]$builder.Append($script:SecretSymbol[$okm[3] % $script:SecretSymbol.Length])
    for ($index = 4; $index -lt $script:SecretLength; $index++) {
        [void]$builder.Append($alphabet[$okm[$index] % $alphabet.Length])
    }
    return $builder.ToString()
}

# ---------------------------------------------------------------------------
# the flow of the templates
# ---------------------------------------------------------------------------

# The op of each template stage that runs in the password task when the
# stage is run: the op whose result file records the stage's outcome
# when the session that ran it dropped.
$script:StageTaskOp = @{ '2' = 's2-promote'; '3' = 's3-recyclebin'; '4' = 's4-laps'; '7' = 's7-read' }

# The read a resumed stage 3 or 4 runs first, in the password task, so a
# stage stopped after its irreversible write goes on from the state it
# left instead of writing again (F1 of the stage 4 triage; bug hunt R1).
# A run is refused while one of them still runs (X-F1).
$script:StageReadOp = @{ '3' = 's3-state'; '4' = 's4-state' }

# The ops of stage 2 that run in the password task after a boot.  Their
# result files are cleared before each rebooting entry of stage 2, so a
# result file found after a boot is the one of an op of that boot: a
# status whose session dropped while one of them ran records from it.
$script:PostBootOps = @('s2-groups', 's2-genid', 's2-read')

# The stages whose task op is followed by a reboot: a status that records
# such a stage's result file writes rebooting and restarts (stage 4 since
# the maintainer's decision of 2026-11-13).
$script:RebootingTaskStages = @('2', '4')

# The ops of stages 5 and 6, each in the password task, in the order the
# stage runs them.  Stages 5 and 6 are not on the status record path
# (DESIGN-1.5 names stages 2, 3 and 4 for it; an open point for the maintainer).
$script:StageOwnOps = @{ '5' = @('s5-structure'); '6' = @('s6-gpo-domain', 's6-gpo-dc', 's6-read'); '9' = @('s9-da') }

function Test-NewtonTemplateStage {
    param([string]$Stage)
    return ($script:TemplateStages -ccontains $Stage)
}

function Get-NewtonRebootCount {
    # The rebooting entries of one stage since its last start: the phase
    # of a stage that reboots more than once (stage 2).
    param($Entries, [string]$Stage)
    $count = 0
    foreach ($entry in $Entries) {
        $one = $entry['record']
        if ([string](Get-NewtonField $one 'stage') -cne $Stage) { continue }
        $state = [string](Get-NewtonField $one 'state')
        if ($state -eq $script:StartedState) { $count = 0 }
        elseif ($state -eq $script:RebootingState) { $count = $count + 1 }
    }
    return $count
}

function Get-NewtonTaskVerdict {
    # The verdict of an op whose task did not end: not_started stops the
    # stage (nothing ran); running marks the verdict running, and the
    # caller decides what that means for the stage.  $null when the op
    # ended and its output is to be parsed.  $Task names the task of the
    # op: the password task, or the SYSTEM task.
    param([string]$Op, $Ran, [string]$Task = 'the password task')
    $outcome = [string]$Ran['outcome']
    if ([string]::IsNullOrEmpty($outcome) -or ($outcome -eq 'ended')) { return $null }
    $verdict = New-NewtonVerdict
    $found = [string]$Ran['found']
    if ($outcome -eq 'running') {
        $verdict['running'] = $true
        $detail = $Task + ' still runs; it is left to finish'
        if (-not [string]::IsNullOrEmpty($found)) { $detail = $Task + ' ' + $found }
        Add-NewtonCheck $verdict $Op $true $detail ''
        return $verdict
    }
    if ($outcome -eq 'not_started') {
        $detail = $Task + ' did not start within ' + [string]$script:TaskStartSeconds + ' s'
        if (-not [string]::IsNullOrEmpty($found)) { $detail = $detail + ': ' + $found }
        Add-NewtonCheck $verdict $Op $false $detail 'op_failed'
        return $verdict
    }
    Add-NewtonCheck $verdict $Op $false ($Task + ' has no known outcome') 'op_failed'
    return $verdict
}

function Invoke-NewtonOp {
    # Render, run and read back one op.  With -FromEarlier (the post-boot
    # ops of stage 2), the result file of a run of this boot whose session
    # dropped is read instead, and the op does not run again.  With
    # -AsSystem the op runs in the SYSTEM task (DESIGN-1.5 point 83,
    # 2026-11-23); only s7-dc asks for it.
    param([string]$Op, $Values, [bool]$AsTask, [int64]$NotBefore, $Groups,
        [int]$WaitSeconds = $script:TaskWaitSeconds, [switch]$FromEarlier, [switch]$AsSystem)
    $ran = $null
    if ($FromEarlier) { $ran = Get-NewtonEarlierRun -Op $Op }
    if ($null -eq $ran) {
        $script = Get-NewtonOpScript -Op $Op -Values $Values
        $ran = Invoke-NewtonStageOp -Op $Op -Script $script -AsTask $AsTask -WaitSeconds $WaitSeconds -AsSystem:$AsSystem
    }
    $task = 'the password task'
    if ($AsSystem) { $task = 'the SYSTEM task' }
    $taskVerdict = Get-NewtonTaskVerdict -Op $Op -Ran $ran -Task $task
    if ($null -ne $taskVerdict) { return $taskVerdict }
    return (Get-NewtonOpVerdict -Op $Op -Output ([string]$ran['output']) -Values $Values `
        -Now (Get-NewtonNow) -NotBefore $NotBefore -Groups $Groups -Result ([int]$ran['result']))
}

function Get-NewtonEarlierRun {
    # The run of a post-boot op of stage 2 (or of stage 8's s8-read) from an earlier request of
    # this boot, out of its result file, in the shape of
    # Invoke-NewtonStageOp: $null when there is none.  The task it ran in
    # is over (the caller checked) and goes.
    param([string]$Op)
    $earlier = Read-NewtonOpResult -Op $Op
    if ($null -eq $earlier) { return $null }
    Remove-NewtonPasswordTask -Op $Op
    return @{ outcome = 'ended'; result = [int]$earlier['result']; output = [string]$earlier['output']; found = '' }
}

function Complete-NewtonTemplateStage {
    # The terminal entry of a template stage and its answer: done when
    # every check passed, stopped with the code of the first failed
    # check otherwise, rebooting (and the restart) when the stage
    # reboots next.
    param([string]$Run, [string]$Stage, [string]$Digest, [string]$Checkpoint, [string]$Boot,
        [hashtable]$Verdict, [bool]$Reboot, [string]$Phase = '')
    if ($Reboot -and ($Stage -eq '2') -and [string]::IsNullOrEmpty([string]$Verdict['code'])) {
        # The result files of the post-boot ops go before the rebooting
        # entry: one found after the boot is one of that boot.
        try {
            foreach ($postBootOp in $script:PostBootOps) { Clear-NewtonOpResult -Op $postBootOp }
        } catch {
            $cleared = New-NewtonErrorVerdict ('the result files of the post-boot ops were not cleared: ' + [string]$_.Exception.Message)
            $cleared['checks'].InsertRange(0, $Verdict['checks'])
            $Verdict = $cleared
            $Reboot = $false
        }
    }
    $checks = @($Verdict['checks'].ToArray())
    if ($Verdict.ContainsKey('running') -and [bool]$Verdict['running']) {
        # The op of the stage still runs in its password task: the stage
        # stays started, with no terminal entry.  For stages 2, 3 and 4 a
        # status request records the outcome from the op's own result file
        # (Test-NewtonRecordStage); stages 5 and 6 are not on that path and
        # stay started until a resume plan runs them (DESIGN-1.5, open
        # point 6).
        return (New-NewtonAnswer -Ok $true -Status $script:AnswerStarted -Code '' -Checks $checks)
    }
    $code = [string]$Verdict['code']
    if (-not [string]::IsNullOrEmpty($code)) {
        $null = Add-NewtonJournalEntry -Run $Run -Seq (Get-NewtonNextSeq -Run $Run) -Stage $Stage `
            -State $script:StoppedState -Reason $code -Digest $Digest -Checkpoint $Checkpoint `
            -Boot $Boot -Checks $checks -Phase $Phase
        return (New-NewtonAnswer -Ok $false -Status $script:AnswerStopped -Code $code -Checks $checks)
    }
    if ($Reboot) {
        $null = Add-NewtonJournalEntry -Run $Run -Seq (Get-NewtonNextSeq -Run $Run) -Stage $Stage `
            -State $script:RebootingState -Reason '' -Digest $Digest -Checkpoint $Checkpoint `
            -Boot $Boot -Checks $checks -Phase $Phase
        $restarted = $false
        try { $restarted = [bool](Invoke-NewtonRestart) } catch { $restarted = $false }
        if (-not $restarted) {
            # No restart is coming: the stage stops now rather than wait
            # for a boot until the grace of its token passes.
            $stop = New-NewtonErrorVerdict 'the restart of the server was refused'
            $stopChecks = @($checks) + @($stop['checks'].ToArray())
            $null = Add-NewtonJournalEntry -Run $Run -Seq (Get-NewtonNextSeq -Run $Run) -Stage $Stage `
                -State $script:StoppedState -Reason 'error' -Digest $Digest -Checkpoint $Checkpoint `
                -Boot $Boot -Checks $stopChecks -Phase $Phase
            return (New-NewtonAnswer -Ok $false -Status $script:AnswerStopped -Code 'error' -Checks $stopChecks)
        }
        return (New-NewtonAnswer -Ok $true -Status $script:AnswerRebooting -Code '' -Checks $checks)
    }
    $null = Add-NewtonJournalEntry -Run $Run -Seq (Get-NewtonNextSeq -Run $Run) -Stage $Stage `
        -State $script:DoneState -Reason '' -Digest $Digest -Checkpoint $Checkpoint `
        -Boot $Boot -Checks $checks -Phase $Phase
    return (New-NewtonAnswer -Ok $true -Status $script:AnswerDone -Code '' -Checks $checks)
}

function New-NewtonErrorVerdict {
    # An error while a stage ran: the stage stops with the reason error.
    param([string]$Message)
    $verdict = New-NewtonVerdict
    Add-NewtonCheck $verdict 'error' $false $Message 'error'
    return $verdict
}

function Get-NewtonTaskWait {
    # The wait for a run's password task: TaskWaitSeconds, and never past
    # the EXP of the token less TaskAnswerMarginSeconds.
    param([hashtable]$Request)
    return [int][Math]::Min([int64]$script:TaskWaitSeconds,
        [Math]::Max([int64]0, ([int64]$Request['exp'] - (Get-NewtonNow) - $script:TaskAnswerMarginSeconds)))
}

function Invoke-NewtonResumeRead {
    # The read of a resumed stage 3 or 4 (StageReadOp): its verdict, with
    # phase 'before' or 'after' when the state is one of the two measured
    # ones.  A read still running at its limit stops readback_failed:
    # nothing was written.
    param([string]$Stage, $Values, [int64]$NotBefore, [int]$WaitSeconds)
    $op = [string]$script:StageReadOp[$Stage]
    $state = Invoke-NewtonOp -Op $op -Values $Values -AsTask $true -NotBefore $NotBefore -Groups @() -WaitSeconds $WaitSeconds
    if ($state.ContainsKey('running')) {
        $state = New-NewtonVerdict
        Add-NewtonCheck $state $op $false 'the read of the state did not end in its wait' 'readback_failed'
    }
    return $state
}

function Invoke-NewtonTemplateRun {
    # The run of a template stage: the started entry, the ops, then the
    # terminal entry.  Stages 0, 3, 5 and 6 end done or stopped; stages 1, 2
    # and 4 end rebooting and finish in Invoke-NewtonTemplateStatus.
    param([hashtable]$Request, $Values, [string]$Digest, [string]$Checkpoint, $Entries = @())
    $run = [string]$Request['run']
    $stage = [string]$Request['stage']
    $nbf = [int64]$Request['nbf']
    $boot = Format-NewtonBootTime (Get-NewtonBootTime)

    # A stage 3 or 4 that ran before (it stopped, or it was left started)
    # and is run again by a resume plan reads the state first (F1 of the
    # stage 4 triage, bug hunt R1): the before-checks of
    # s3-recyclebin and s4-laps would not match a state they already
    # wrote, and the write is not made twice.
    $resumed = $false
    foreach ($entry in @($Entries)) {
        $one = $entry['record']
        if (([string](Get-NewtonField $one 'stage') -ceq $stage) -and
            ([string](Get-NewtonField $one 'state') -ne $script:CheckpointedState)) { $resumed = $true }
    }

    # A stage 2 run whose token cannot hold the promotion and the answer
    # margin is refused before anything starts (PromotionMinimumSeconds).
    if (($stage -eq '2') -and
        (([int64]$Request['exp'] - (Get-NewtonNow)) -lt ($script:PromotionMinimumSeconds + $script:TaskAnswerMarginSeconds))) {
        Throw-NewtonRefusal 'window_short' ('the token leaves less than ' +
            [string]($script:PromotionMinimumSeconds + $script:TaskAnswerMarginSeconds) + ' s: a promotion needs a fresh token')
    }

    # The password task of the stage from an earlier request (a session
    # that dropped) still runs: the stage is not run a second time over
    # it.  Otherwise the result file of an earlier run goes before the
    # started entry, so only this run's op can complete the stage.
    # Stage 2 also has its post-boot tasks: one left running by a stop
    # (its wait ended) would be killed by the restart of a resumed run,
    # and its result file written after the clear of the rebooting entry.
    if ($script:StageTaskOp.ContainsKey($stage)) {
        $taskOp = [string]$script:StageTaskOp[$stage]
        $taskOps = @($taskOp)
        if ($stage -eq '2') { $taskOps = $taskOps + $script:PostBootOps }
        if ($script:StageReadOp.ContainsKey($stage)) { $taskOps = $taskOps + @([string]$script:StageReadOp[$stage]) }
        foreach ($one in $taskOps) {
            if (Test-NewtonPasswordTaskRunning -Op $one) {
                Throw-NewtonRefusal 'out_of_order' ('the password task NewtonBuild-' + $one + ' of the stage still runs from an earlier request')
            }
        }
        Clear-NewtonOpResult -Op $taskOp
    }
    # Stages 5 and 6 run their ops in the password task too: one still
    # running from an earlier request refuses the run, and their result
    # files of an earlier run go before the started entry.
    if ($script:StageOwnOps.ContainsKey($stage)) {
        foreach ($one in $script:StageOwnOps[$stage]) {
            if (Test-NewtonPasswordTaskRunning -Op $one) {
                Throw-NewtonRefusal 'out_of_order' ('the password task NewtonBuild-' + $one + ' of the stage still runs from an earlier request')
            }
        }
        foreach ($one in $script:StageOwnOps[$stage]) { Clear-NewtonOpResult -Op $one }
    }

    $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) `
        -Stage $stage -State $script:StartedState -Reason '' -Digest $Digest `
        -Checkpoint $Checkpoint -Boot $boot -Checks @()

    $reboot = $false
    $verdict = $null
    try {
        # The wait for the op's password task ends before the EXP of the
        # token, less the margin for the answer: a 'running' outcome comes
        # back inside the window, and the status record path takes it
        # from there (TaskWaitSeconds).  Stage 2 computes it again after
        # s2-role, so the role read's seconds come out of the wait and
        # not out of the margin.
        $wait = Get-NewtonTaskWait -Request $Request
        switch ($stage) {
            '0' { $verdict = Invoke-NewtonOp -Op 's0-read' -Values $Values -AsTask $false -NotBefore $nbf -Groups @() }
            '1' {
                $verdict = Invoke-NewtonOp -Op 's1-base' -Values $Values -AsTask $false -NotBefore $nbf -Groups @()
                $reboot = $true
            }
            '2' {
                # The role first: a resumed stage 2 whose promotion
                # already succeeded (it stopped after it) skips the
                # promotion and goes on to the reboot and the
                # post-promotion steps; any role but the workgroup server
                # or this plan's forest root stops the stage.
                $role = Invoke-NewtonOp -Op 's2-role' -Values $Values -AsTask $false -NotBefore $nbf -Groups @()
                if (-not [string]::IsNullOrEmpty([string]$role['code'])) {
                    $verdict = $role
                } elseif ($role.ContainsKey('promoted') -and [bool]$role['promoted']) {
                    $verdict = $role
                    $reboot = $true
                } else {
                    # The DSRM secret is derived here from K and the salt
                    # of the build's secrets, the first plan's digest
                    # (DESIGN-1.5 "Secrets", open point 71), and reaches the task
                    # only through the DPAPI file, which the op deletes.
                    $secretFile = [string]$Values['SecretFile']
                    $secret = Get-NewtonDerivedSecret -Key (Get-NewtonKeyBytes) -Digest (Get-NewtonRequestSecrets) -Info $script:DsrmInfo
                    $wait = Get-NewtonTaskWait -Request $Request
                    try {
                        Write-NewtonSecretFile -Path $secretFile -Secret $secret
                        $secret = $null
                        $verdict = Invoke-NewtonOp -Op 's2-promote' -Values $Values -AsTask $true -NotBefore $nbf -Groups @() -WaitSeconds $wait
                    } finally {
                        $secret = $null
                        Remove-NewtonSecretFile -Path $secretFile
                    }
                    $verdict['checks'].InsertRange(0, $role['checks'])
                    $reboot = $true
                }
            }
            '3' {
                # A resumed stage 3 whose Enable-ADOptionalFeature already
                # succeeded (it stopped after it) is done on the state it
                # reads; one in the state before runs the op; any other
                # state stops readback_failed with no write.
                $state = $null
                if ($resumed) { $state = Invoke-NewtonResumeRead -Stage $stage -Values $Values -NotBefore $nbf -WaitSeconds $wait }
                if (($null -ne $state) -and (-not [string]::IsNullOrEmpty([string]$state['code']))) {
                    $verdict = $state
                } elseif (($null -ne $state) -and ([string]$state['phase'] -ceq 'after')) {
                    $verdict = $state
                } else {
                    $wait = Get-NewtonTaskWait -Request $Request
                    $verdict = Invoke-NewtonOp -Op 's3-recyclebin' -Values $Values -AsTask $true -NotBefore $nbf -Groups @() -WaitSeconds $wait
                    if ($null -ne $state) { $verdict['checks'].InsertRange(0, $state['checks']) }
                }
            }
            '4' {
                # The maintainer's decision, 2026-11-13: stage 4 ends with a reboot, so
                # the S4U key login loses Enterprise and Schema Admins
                # (MEASURED-1.5: it keeps them until a reboot).
                $state = $null
                if ($resumed) { $state = Invoke-NewtonResumeRead -Stage $stage -Values $Values -NotBefore $nbf -WaitSeconds $wait }
                if (($null -ne $state) -and (-not [string]::IsNullOrEmpty([string]$state['code']))) {
                    $verdict = $state
                } elseif (($null -ne $state) -and ([string]$state['phase'] -ceq 'after')) {
                    # s4-laps succeeded before the stop: on to the reboot and
                    # the group read; s4-laps does not run again.
                    $verdict = $state
                    $reboot = $true
                } else {
                    $wait = Get-NewtonTaskWait -Request $Request
                    $verdict = Invoke-NewtonOp -Op 's4-laps' -Values $Values -AsTask $true -NotBefore $nbf -Groups @() -WaitSeconds $wait
                    if ($null -ne $state) { $verdict['checks'].InsertRange(0, $state['checks']) }
                    $reboot = $true
                }
            }
            '5' {
                # The owner's admin secret is derived here from K and the
                # salt of the build's secrets, the first plan's digest
                # (DESIGN-1.5 "Secrets", open point 71), and reaches the task
                # only through its DPAPI file, which the op deletes.
                $secretFile = [string]$Values['AdminSecretFile']
                $secret = Get-NewtonDerivedSecret -Key (Get-NewtonKeyBytes) -Digest (Get-NewtonRequestSecrets) -Info $script:AdminInfo
                try {
                    Write-NewtonSecretFile -Path $secretFile -Secret $secret
                    $secret = $null
                    $verdict = Invoke-NewtonOp -Op 's5-structure' -Values $Values -AsTask $true -NotBefore $nbf -Groups @() -WaitSeconds $wait
                } finally {
                    $secret = $null
                    Remove-NewtonSecretFile -Path $secretFile
                }
            }
            '6' {
                # The GPOs one after the other, then the read of the policy
                # applied; the first op that stops or still runs ends it.
                $verdict = New-NewtonVerdict
                foreach ($op in $script:StageOwnOps['6']) {
                    $wait = Get-NewtonTaskWait -Request $Request
                    $one = Invoke-NewtonOp -Op $op -Values $Values -AsTask $true -NotBefore $nbf -Groups @() -WaitSeconds $wait
                    $verdict['checks'].AddRange($one['checks'])
                    if ($one.ContainsKey('running')) { $verdict['running'] = $true; break }
                    if (-not [string]::IsNullOrEmpty([string]$one['code'])) { $verdict['code'] = [string]$one['code']; break }
                }
            }
            '9' {
                # The cleanup (MEASURED-1.5, stage 9): DC1's newton-build
                # leaves Domain Admins in its password task; DC2 makes no
                # removal (the membership is domain-wide, and DC2 runs no
                # password task after its promotion).  Then the SYSTEM task,
                # which acts after this answer has left; on DC1 it deletes
                # the domain account last.  Nothing is answered after it.
                $dc1 = ([string]$Request['role'] -ceq 'dc1')
                $verdict = New-NewtonVerdict
                if ($dc1) {
                    $one = Invoke-NewtonOp -Op 's9-da' -Values $Values -AsTask $true -NotBefore $nbf -Groups @() -WaitSeconds $wait
                    $verdict['checks'].AddRange($one['checks'])
                    if ($one.ContainsKey('running')) { $verdict['running'] = $true }
                    if (-not [string]::IsNullOrEmpty([string]$one['code'])) { $verdict['code'] = [string]$one['code'] }
                }
                if ((-not $verdict.ContainsKey('running')) -and [string]::IsNullOrEmpty([string]$verdict['code'])) {
                    $cleanup = Get-NewtonCleanupScript -DeleteAccount $dc1
                    $Values['CleanupB64'] = [Convert]::ToBase64String((New-Object System.Text.UTF8Encoding $false).GetBytes($cleanup))
                    $Values['CleanupScript'] = $script:CleanupScriptPath
                    $Values['CleanupTask'] = $script:CleanupTaskName
                    $one = Invoke-NewtonOp -Op 's9-register' -Values $Values -AsTask $false -NotBefore $nbf -Groups @()
                    $verdict['checks'].AddRange($one['checks'])
                    if (-not [string]::IsNullOrEmpty([string]$one['code'])) { $verdict['code'] = [string]$one['code'] }
                }
            }
            default { Throw-NewtonRefusal 'schema' 'the stage has no template' }
        }
    } catch {
        $verdict = New-NewtonErrorVerdict ([string]$_.Exception.Message)
        $reboot = $false
    }
    return (Complete-NewtonTemplateStage -Run $run -Stage $stage -Digest $Digest -Checkpoint $Checkpoint `
        -Boot $boot -Verdict $verdict -Reboot $reboot)
}

function Invoke-NewtonTemplateStatus {
    # The post-boot work of a template stage that waited for a reboot,
    # run once the boot time has advanced.
    #   stage 1: the read-back.
    #   stage 2, first boot: the three groups, in the password task,
    #     then the second reboot (the S4U groups need it; MEASURED-1.5).
    #   stage 2, later boots: msDS-GenerationId; absent means one more
    #     reboot (at most GenerationIdReboots), present means the
    #     read-back.
    #   stage 4: the build account's groups in the directory and in the
    #     token of the S4U key login (the maintainer's decision, 2026-11-13).
    param([hashtable]$Request, $Values, [string]$Digest, [string]$Checkpoint, $Entries)
    $run = [string]$Request['run']
    $stage = [string]$Request['stage']
    $nbf = [int64]$Request['nbf']
    $boot = Format-NewtonBootTime (Get-NewtonBootTime)
    $reboot = $false
    $verdict = $null
    try {
        if ($stage -eq '1') {
            $verdict = Invoke-NewtonOp -Op 's1-read' -Values $Values -AsTask $false -NotBefore $nbf -Groups @()
        } elseif ($stage -eq '2') {
            # A post-boot op of an earlier request of this boot still runs
            # in its task (that request's session dropped): the stage is
            # still in progress.  Nothing runs and nothing is written; the
            # status after the task ends records from its result file.
            foreach ($postBootOp in $script:PostBootOps) {
                if (Test-NewtonPasswordTaskRunning -Op $postBootOp) {
                    $check = [ordered]@{ name = $postBootOp; ok = $true
                        detail = 'the password task NewtonBuild-' + $postBootOp + ' of an earlier request still runs; the stage is in progress' }
                    return (New-NewtonAnswer -Ok $true -Status $script:AnswerRebooting -Code '' -Checks @($check))
                }
            }
            $phase = Get-NewtonRebootCount -Entries $Entries -Stage $stage
            if (-not (Wait-NewtonDirectory)) {
                $verdict = New-NewtonVerdict
                Add-NewtonCheck $verdict 'directory' $false 'Get-ADDomain did not answer' 'directory_unready'
            } elseif ($phase -le 1) {
                $verdict = Invoke-NewtonOp -Op 's2-groups' -Values $Values -AsTask $true -NotBefore $nbf -Groups @() -FromEarlier
                $reboot = $true
            } else {
                $ran = Get-NewtonEarlierRun -Op 's2-genid'
                if ($null -eq $ran) {
                    $script = Get-NewtonOpScript -Op 's2-genid' -Values $Values
                    $ran = Invoke-NewtonStageOp -Op 's2-genid' -Script $script -AsTask $true
                }
                $lines = Get-NewtonOutputLines ([string]$ran['output'])
                $taskVerdict = Get-NewtonTaskVerdict -Op 's2-genid' -Ran $ran
                if ($null -ne $taskVerdict) {
                    $verdict = $taskVerdict
                } elseif (Test-NewtonOpFailed -Result ([int]$ran['result']) -Lines $lines) {
                    $verdict = New-NewtonVerdict
                    Add-NewtonCheck $verdict 's2-genid' $false ([string](Find-NewtonLine $lines 'FAIL: ')) 'op_failed'
                } elseif (-not (Test-NewtonGenerationId $lines)) {
                    $verdict = New-NewtonVerdict
                    if (($phase - 1) -le $script:GenerationIdReboots) {
                        Add-NewtonCheck $verdict 'generation_id' $true 'absent: one more reboot' 'generation_id_missing'
                        $reboot = $true
                    } else {
                        Add-NewtonCheck $verdict 'generation_id' $false 'absent after every reboot' 'generation_id_missing'
                    }
                } else {
                    $verdict = Invoke-NewtonOp -Op 's2-read' -Values $Values -AsTask $true -NotBefore $nbf `
                        -Groups (Get-NewtonOwnGroups) -FromEarlier
                    $verdict['checks'].Insert(0, [ordered]@{ name = 'generation_id'; ok = $true; detail = 'present' })
                }
            }
        } elseif ($stage -eq '4') {
            # The read of the groups after the boot (the maintainer's decision,
            # 2026-11-13): the directory, in an op of this session, and
            # the token of this session itself.  It never restarts.
            if (-not (Wait-NewtonDirectory)) {
                $verdict = New-NewtonVerdict
                Add-NewtonCheck $verdict 'directory' $false 'Get-ADDomain did not answer' 'directory_unready'
            } else {
                $own = @()
                try { $own = @(Get-NewtonOwnGroups) } catch { $own = @() }
                $verdict = Invoke-NewtonOp -Op 's4-groups' -Values $Values -AsTask $false -NotBefore $nbf -Groups $own
            }
        } else {
            Throw-NewtonRefusal 'schema' 'the stage has no post-boot template'
        }
    } catch {
        $verdict = New-NewtonErrorVerdict ([string]$_.Exception.Message)
        $reboot = $false
    }
    if ($verdict.ContainsKey('running') -and [bool]$verdict['running']) {
        # A post-boot op still runs in its task at the limit: the stage
        # waits for a boot, not for a task, so it stops here, and the
        # task is left to finish (none of the post-boot ops is killed).
        $still = New-NewtonVerdict
        foreach ($check in $verdict['checks']) {
            Add-NewtonCheck $still ([string]$check['name']) $false ([string]$check['detail']) 'op_failed'
        }
        $verdict = $still
    }
    if ([string]::IsNullOrEmpty([string]$verdict['code']) -eq $false) { $reboot = $false }
    return (Complete-NewtonTemplateStage -Run $run -Stage $stage -Digest $Digest -Checkpoint $Checkpoint `
        -Boot $boot -Verdict $verdict -Reboot $reboot)
}

function Test-NewtonRecordStage {
    # True for a template stage whose op runs in the password task, left
    # started: a status request records it from the op's result file.
    param([string]$Stage, $State)
    if ([string]$State['state'] -ne $script:StartedState) { return $false }
    if (-not [string]::IsNullOrEmpty((Get-NewtonStageTablePath))) { return $false }
    if (-not $script:StageTaskOp.ContainsKey($Stage)) { return $false }
    if ($Stage -ceq $script:ReplicaStage) {
        # Stage 7 is recorded from the result file of its own op: DC1's
        # read-back (s7-read) and DC2's own read (s7-dc, in the SYSTEM
        # task).  Its provision and install end in the run that made them
        # (Invoke-NewtonReplicaRun).
        if (@('s7_read', 's7_dc') -cnotcontains (Get-NewtonReplicaPhase $State)) { return $false }
    }
    return [bool](Test-NewtonWindowsHost)
}

function Test-NewtonStartedUnder {
    # True when the stage was started under the plan of this digest.
    param($State, [string]$Digest)
    return ([string](Get-NewtonField $State['record'] 'digest') -ceq $Digest)
}

function Invoke-NewtonTemplateRecord {
    # The status of a template stage left started.  It records what
    # already happened and never runs an op.  While its password task
    # runs, the stage is started.  Once the task is over, the result file
    # the op wrote as its last act is parsed exactly as the helper that
    # ran the stage would have parsed it, and the terminal entry is
    # written: done or stopped, or for stages 2 and 4 rebooting and the
    # restart.
    # No result file means the op did not run to its end: stopped.
    #
    # -PastBound: the status came after the EXP of the token plus
    # PostBootGraceSeconds.  A task still running is a refusal that names
    # it (never done, nothing written).  A result file is still recorded,
    # except that stages 2 and 4 do not restart (their post-boot work
    # would be refused): an op that succeeded stops grace_passed.  No result
    # file: stopped grace_passed.
    param([hashtable]$Request, $Values, [string]$Digest, [string]$Checkpoint, [string]$Phase = '', [switch]$PastBound)
    $run = [string]$Request['run']
    $stage = [string]$Request['stage']
    $nbf = [int64]$Request['nbf']
    $op = [string]$script:StageTaskOp[$stage]
    $task = 'the password task'
    if ($stage -ceq $script:ReplicaStage) {
        # Stage 7's record path: DC1's read-back (s7-read) and DC2's own
        # read (s7-dc), each from the result file of its own op.
        if ($Phase -ceq 's7_dc') {
            $op = 's7-dc'
            $task = 'the SYSTEM task'
        }
    }
    if (Test-NewtonPasswordTaskRunning -Op $op) {
        if ($PastBound) {
            $check = [ordered]@{ name = $op; ok = $false
                detail = $task + ' NewtonBuild-' + $op + ' still runs past the EXP of the token plus the grace' }
            return (New-NewtonAnswer -Ok $false -Status $script:AnswerRefused -Code 'expired' -Checks @($check))
        }
        $check = [ordered]@{ name = $op; ok = $true; detail = $task + ' of the stage still runs' }
        return (New-NewtonAnswer -Ok $true -Status $script:AnswerStarted -Code '' -Checks @($check))
    }
    $boot = Format-NewtonBootTime (Get-NewtonBootTime)
    $reboot = $false
    $verdict = $null
    try {
        $ran = Read-NewtonOpResult -Op $op
        Remove-NewtonPasswordTask -Op $op
        if ($stage -eq '2') { Remove-NewtonSecretFile -Path ([string]$Values['SecretFile']) }
        if ($null -eq $ran) {
            $verdict = New-NewtonVerdict
            if ($PastBound) {
                Add-NewtonCheck $verdict $op $false 'the op wrote no result file, and the grace of the token has passed' $script:GracePassedReason
            } else {
                Add-NewtonCheck $verdict $op $false 'the op wrote no result file: it did not run to its end' 'op_failed'
            }
        } else {
            $verdict = Get-NewtonOpVerdict -Op $op -Output ([string]$ran['output']) -Values $Values `
                -Now (Get-NewtonNow) -NotBefore $nbf -Groups @() -Result ([int]$ran['result'])
            $reboot = ($script:RebootingTaskStages -ccontains $stage)
            if ($reboot -and $PastBound -and [string]::IsNullOrEmpty([string]$verdict['code'])) {
                Add-NewtonCheck $verdict 'grace' $false 'the grace of the token has passed: no restart' $script:GracePassedReason
                $reboot = $false
            }
        }
    } catch {
        $verdict = New-NewtonErrorVerdict ([string]$_.Exception.Message)
        $reboot = $false
    }
    $entryPhase = ''
    if ($stage -ceq $script:ReplicaStage) {
        # The phase of the stage's own op: s7_read for DC1's read-back,
        # s7_dc for DC2's own read.
        $entryPhase = $Phase
        if ([string]::IsNullOrEmpty($entryPhase)) { $entryPhase = 's7_read' }
    }
    return (Complete-NewtonTemplateStage -Run $run -Stage $stage -Digest $Digest -Checkpoint $Checkpoint `
        -Boot $boot -Verdict $verdict -Reboot $reboot -Phase $entryPhase)
}

# ---------------------------------------------------------------------------
# the actions
# ---------------------------------------------------------------------------

function Invoke-NewtonDroppedConnection {
    # The fake of a dropped connection (the fake table of task 3): the
    # terminal entry of the stage is on the disk and the answer never
    # arrives.  A template stage whose session drops while its password
    # task runs is recorded by a status request instead, from the result
    # file the op writes (Invoke-NewtonTemplateRecord).
    [Console]::Error.WriteLine('newton: the connection dropped after the terminal entry of the stage')
    exit 3
}

function Invoke-NewtonCheckpoint {
    # The checkpoint of a stage: the helper takes it itself, under the
    # plan token, and records its id in the journal.  The token of the
    # stage is the token of the stage digest over that id.
    param([hashtable]$Request, [hashtable]$Plan, [string]$Digest, $Entries)
    $run = [string]$Request['run']
    $stage = [string]$Request['stage']
    $graph = $Request['graph']

    # The checkpoint of a stage is taken before the stage runs, and
    # only for an irreversible stage: a read or a reversible stage is
    # not checkpointed.
    if ((Get-NewtonDesignKind -Stage $stage) -ne $script:IrreversibleKind) {
        Throw-NewtonRefusal 'out_of_order' 'the stage takes no checkpoint'
    }
    $next = Get-NewtonNextStage -Graph $graph -Entries $Entries
    if ($stage -cne $next) {
        Throw-NewtonRefusal 'out_of_order' 'the stage is not the next one of the graph'
    }

    # A stage that waits for a reboot takes no checkpoint: it is in
    # flight under the id the owner signed, and it has its own grace
    # path.  A stage left started with no terminal entry takes no
    # checkpoint under the plan of the run either, but a resume plan
    # (its resume_from set and its start_stage this stage) takes one,
    # or a stage left started could never be resumed.  The plan of the
    # request already passed Assert-NewtonPlanOfRun, so a plan that is
    # not the plan of the run is a resume plan of this run.
    $stageState = [string](Get-NewtonStageState -Entries $Entries -Stage $stage)['state']
    if ($stageState -eq $script:StartedState) {
        $resumeFrom = ''
        if ($Plan.ContainsKey('resume_from')) { $resumeFrom = [string]$Plan['resume_from'] }
        $startStage = ''
        if ($Plan.ContainsKey('start_stage')) { $startStage = [string]$Plan['start_stage'] }
        $journalDigest = Get-NewtonJournalDigest $Entries
        if (($journalDigest -ceq $Digest) -or [string]::IsNullOrEmpty($resumeFrom) -or
            ($resumeFrom -cne $journalDigest) -or ($startStage -cne $stage)) {
            Throw-NewtonRefusal 'out_of_order' 'the stage is in flight; it takes no checkpoint'
        }
    } elseif (($stageState -ne '') -and ($stageState -ne $script:StoppedState)) {
        Throw-NewtonRefusal 'out_of_order' 'the stage is in flight; it takes no checkpoint'
    }

    # One checkpoint per stage per plan: the newest id would replace the
    # one the token of the owner was minted over and void that token.
    if (-not [string]::IsNullOrEmpty(
            (Get-NewtonCheckpointId -Entries $Entries -Stage $stage -Digest $Digest))) {
        Throw-NewtonRefusal 'out_of_order' 'the stage already holds a checkpoint of this plan'
    }

    # A checkpoint Newton took through a hypervisor adapter (Hyper-V,
    # Proxmox) is named by the request, and the helper records its id: the
    # owner's stage token is over the id the stage approval verified
    # through the adapter itself, so an id that is not that one opens
    # nothing.  A server without a hypervisor takes its own backup, which
    # is not built yet (open point 2 of task 7), so it names none.
    $seq = Get-NewtonNextSeq -Run $run
    $id = ''
    if ($Request.ContainsKey('checkpoint_id')) {
        $index = Get-NewtonPlanServerIndex -Plan $Plan -Role ([string]$Request['role'])
        $method = [string]$Plan['servers.' + [string]$index + '.checkpoint']
        if (($method -cne 'hyperv') -and ($method -cne 'proxmox')) {
            Throw-NewtonRefusal 'schema' 'a server without a hypervisor names no checkpoint'
        }
        $id = [string]$Request['checkpoint_id']
    } else {
        # The template of the wbadmin checkpoint is not in the helper
        # yet.  The fake id of the tests must not reach the journal of a
        # server, so a server with no fake table takes no checkpoint.
        if ([string]::IsNullOrEmpty((Get-NewtonStageTablePath))) {
            Throw-NewtonRefusal 'schema' 'the checkpoint of a stage is not built yet'
        }
        $id = 'fake-cp-' + $stage + '-' + [string]$seq
    }
    $name = ''
    if ($Request.ContainsKey('checkpoint_name')) { $name = [string]$Request['checkpoint_name'] }
    $record = Add-NewtonJournalEntry -Run $run -Seq $seq -Stage $stage `
        -State $script:CheckpointedState -Reason '' -Digest $Digest -Checkpoint $id `
        -Boot (Format-NewtonBootTime (Get-NewtonBootTime)) -Checks @() -CheckpointName $name
    $check = @{ name = 'checkpoint'; ok = $true; detail = [string]$record['checkpoint'] }
    return (New-NewtonAnswer -Ok $true -Status $script:AnswerCheckpointed -Code '' -Checks @($check))
}

# ---------------------------------------------------------------------------
# the DC reads of a checkpoint verify (PLAN-1.5 task 8 part B0)
# ---------------------------------------------------------------------------

# The stages whose design checkpoint is a DC one, per role (DESIGN-1.5
# "Checkpoints"; checkpoint.KIND_OF_STAGE): DC1's 3, 4, 6 and 7.  DC2's
# stage 7 checkpoint is a workgroup one, and stage 2's is too.
$script:DcCheckpointStages = @{ 'dc1' = @('3', '4', '6', '7'); 'dc2' = @() }

# The biggest text a read answers with.
$script:MaxReadChars = 65536

# A computer name as the plan's hostname grammar allows it.
$script:ComputerNamePattern = '\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?\z'

function Test-NewtonDcReadStage {
    param([string]$Role, [string]$Stage)
    if (-not $script:DcCheckpointStages.ContainsKey($Role)) { return $false }
    return (@($script:DcCheckpointStages[$Role]) -ccontains $Stage)
}

function Get-NewtonComputerName {
    # The name of the computer the read runs on.
    return [string]$env:COMPUTERNAME
}

function Get-NewtonUtcOffsetMinutes {
    # The server's offset from UTC now, in whole minutes (local minus
    # UTC), as checkpoint.py's readers take it.
    return [int][Math]::Round([TimeZoneInfo]::Local.GetUtcOffset([DateTime]::UtcNow).TotalMinutes)
}

function Invoke-NewtonNativeRead {
    # One read-only program of System32, its output one string per line.
    param([string]$Exe, [string[]]$Arguments)
    $path = Join-Path (Join-Path $env:SystemRoot 'System32') $Exe
    $lines = @(& $path @Arguments 2>&1 | ForEach-Object { [string]$_ })
    return @{ exit = [int]$LASTEXITCODE; lines = [string[]]$lines }
}

function Get-NewtonGenIdText {
    # The msDS-GenerationId line of the s2-genid op, of this DC's own
    # computer object, read in the helper's session (MEASURED-1.5 "Stage
    # 4 reboot": the directory read works over the S4U key login once
    # Get-ADDomain answers).  No warning: stdout is the answer.
    Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue
    $computer = Get-ADComputer -Identity (Get-NewtonComputerName) -Properties @('msDS-GenerationId') -ErrorAction Stop
    $g = $computer.'msDS-GenerationId'
    $value = 'absent'
    if ($g) {
        $value = 'present, ' + @($g).Count + ' bytes, ' + ((@($g) | ForEach-Object { ([byte]$_).ToString('x2') }) -join '')
    }
    return ('msDS-GenerationId on ' + [string]$computer.DistinguishedName + ': ' + $value + "`n")
}

function Invoke-NewtonDcRead {
    # One DC read of a checkpoint verify: read-only, in the helper's own
    # session (never an op, never a password task), and nothing is
    # written to the journal.  The stage must hold a checkpoint of this
    # plan already: the verify reads after the checkpoint is taken.
    param([hashtable]$Request, [string]$Digest, $Entries)
    $stage = [string]$Request['stage']
    if ([string]::IsNullOrEmpty((Get-NewtonCheckpointId -Entries $Entries -Stage $stage -Digest $Digest))) {
        Throw-NewtonRefusal 'out_of_order' 'the stage holds no checkpoint of this plan to verify'
    }
    if (-not (Test-NewtonWindowsHost)) {
        Throw-NewtonRefusal 'schema' 'the DC reads run only under Windows'
    }
    $name = [string]$Request['read']
    $text = ''
    try {
        $computer = [string](Get-NewtonComputerName)
        $offset = Get-NewtonUtcOffsetMinutes
        switch ($name) {
            'genid' { $text = Get-NewtonGenIdText }
            'showbackup' {
                $native = Invoke-NewtonNativeRead -Exe 'repadmin.exe' -Arguments @('/showbackup')
                if ([int]$native['exit'] -ne 0) { throw 'repadmin /showbackup failed' }
                $text = ((@($native['lines']) -join "`n") + "`n")
            }
            'versions' {
                $native = Invoke-NewtonNativeRead -Exe 'wbadmin.exe' -Arguments @('get', 'versions')
                if ([int]$native['exit'] -ne 0) { throw 'wbadmin get versions failed' }
                $text = ((@($native['lines']) -join "`n") + "`n")
            }
            default { throw 'not a read' }
        }
    } catch {
        Throw-NewtonRefusal 'readback_failed' ('the ' + $name + ' read failed')
    }
    if ($computer -cnotmatch $script:ComputerNamePattern) {
        Throw-NewtonRefusal 'readback_failed' 'the computer name is outside its grammar'
    }
    if ((-not (Test-NewtonInt $offset)) -or ([int64]$offset -le -1440) -or ([int64]$offset -ge 1440)) {
        Throw-NewtonRefusal 'readback_failed' 'the UTC offset is not whole minutes in range'
    }
    if ($text.Length -gt $script:MaxReadChars) {
        Throw-NewtonRefusal 'readback_failed' 'the read is bigger than the helper answers'
    }
    $answer = New-NewtonAnswer -Ok $true -Status $script:AnswerDone -Code '' -Checks @()
    $answer['read'] = [ordered]@{ name = $name; computer = $computer; utc_offset_minutes = [int]$offset; text = $text }
    return $answer
}

# ---------------------------------------------------------------------------
# the runs and the statuses of stage 7 (option B)
# ---------------------------------------------------------------------------

function Read-NewtonOdjFile {
    # The blob djoin /provision saved, as base64 for the run's answer: the
    # bytes are never written anywhere else, and the caller deletes the
    # file.
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    try {
        if (($bytes.Length -lt 2) -or ($bytes.Length -gt $script:OdjMaxBytes)) {
            throw ('the blob is ' + [string]$bytes.Length + ' bytes, outside 2 to ' + [string]$script:OdjMaxBytes)
        }
        return [Convert]::ToBase64String($bytes)
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Write-NewtonOdjFile {
    # DC2's copy of the blob, for djoin /requestODJ, which deletes it.
    param([string]$Path, [byte[]]$Bytes)
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
}

function Remove-NewtonOdjFile {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
}

function Get-NewtonReplicaValues {
    # The values of the stage 7 ops: the server's own, and the names and
    # addresses of both DCs and the site, out of the plan bytes, each
    # against its grammar.
    param([hashtable]$Plan, [string]$Role, [hashtable]$Request, [bool]$Reuse)
    $values = Get-NewtonStageValues -Plan $Plan -Role $Role
    $hosts = @{}
    foreach ($one in @('dc1', 'dc2')) {
        $index = Get-NewtonPlanServerIndex -Plan $Plan -Role $one
        $key = 'servers.' + [string]$index + '.hostname'
        $name = Get-NewtonPlanValue -Plan $Plan -Key $key -Pattern $script:HostNamePattern
        if ($name -cmatch $script:DigitsPattern) { Throw-NewtonRefusal 'schema' ('the plan value ' + $key + ' is outside its grammar') }
        $hosts[$one] = $name
        if ($one -ceq 'dc1') {
            $values['Dc1Ip'] = Get-NewtonPlanValue -Plan $Plan -Key ('servers.' + [string]$index + '.ip') -Pattern $script:Ipv4Pattern
        }
    }
    $values['Dc1Host'] = [string]$hosts['dc1']
    $values['Dc2Host'] = [string]$hosts['dc2']
    $values['Dc2Fqdn'] = [string]$hosts['dc2'] + '.' + [string]$values['DnsName']
    $values['SiteName'] = Get-NewtonPlanValue -Plan $Plan -Key 'domain.site' -Pattern $script:NamePattern
    if ($Role -ceq 'dc1') { $values['BlobFile'] = $script:OdjFileDc1 } else { $values['BlobFile'] = $script:OdjFileDc2 }
    $values['Reuse'] = $(if ($Reuse) { '1' } else { '0' })
    # The read-back's own bound (the maintainer's decision K17: up to 30 minutes), and
    # never past the EXP of the token plus the grace, less a margin, so the
    # status that records it is inside the token's bound.
    $left = [int64]$Request['exp'] + $script:PostBootGraceSeconds - (Get-NewtonNow) - $script:ReadMarginSeconds
    $values['ReadWaitSeconds'] = [string][Math]::Max([int64]0, [Math]::Min([int64]$script:ReadMaxSeconds, $left))
    $values['ReadPollSeconds'] = [string]$script:ReadPollSeconds
    # DC2's own dcdiag may wait for the first replication to settle, up to
    # DiagMaxSeconds, and never past the token less the margin of one pass:
    # the wait is a hard limit, but the pass that starts before it may end
    # after it.  The read-back's own wait (K17) is the token's time left,
    # untouched by that margin.
    $values['DiagWaitSeconds'] = [string][Math]::Max([int64]0, [Math]::Min([int64]$script:DiagMaxSeconds, $left - $script:DiagPassMarginSeconds))
    $values['DiagPollSeconds'] = [string]$script:DiagPollSeconds
    return $values
}

function Get-NewtonReplicaPhase {
    param($State)
    if ($null -eq $State['record']) { return '' }
    return [string](Get-NewtonField $State['record'] 'phase')
}

function Invoke-NewtonReplicaRun {
    # A run of stage 7.  DC1 makes three under one stage token (the maintainer's
    # decision K19, stage 7 only): the provision, then the install once its
    # journal records the provision ended (s7_provisioned), then the
    # read-back once it records the install ended (s7_installed); any other
    # run of a stage 7 in flight is refused out_of_order.  A resume plan
    # provisions again (djoin /reuse) only over a stage 7 whose last phase
    # is the provision's; DC2 runs the join once, with the blob.
    param([hashtable]$Request, [hashtable]$Plan, [string]$Digest, [string]$Checkpoint, $Entries, [string]$JournalDigest, $State)
    $run = [string]$Request['run']
    $role = [string]$Request['role']
    $stageState = [string]$State['state']
    $phase = Get-NewtonReplicaPhase $State
    $next = Get-NewtonNextStage -Graph $Request['graph'] -Entries $Entries
    if ($next -cne $script:ReplicaStage) {
        Throw-NewtonRefusal 'out_of_order' 'the stage is not the next one of the graph'
    }
    if (-not (Test-NewtonWindowsHost)) {
        Throw-NewtonRefusal 'schema' 'the stage templates of this host are not built yet: they run only under Windows'
    }
    $step = ''
    $reuse = $false
    if ($role -ceq 'dc1') {
        if ($Request.ContainsKey('odj_bytes')) { Throw-NewtonRefusal 'schema' 'only the run of DC2 carries the offline domain join blob' }
        if ($stageState -ceq '') {
            $step = 'provision'
        } elseif ($JournalDigest -ceq $Digest) {
            if (($stageState -ceq $script:StartedState) -and ($phase -ceq 's7_provisioned')) {
                $step = 'install'
            } elseif (($stageState -ceq $script:StartedState) -and ($phase -ceq 's7_installed')) {
                $step = 'read'
            } else {
                Throw-NewtonRefusal 'out_of_order' ('the stage is in flight at ' + $stageState + ' ' + $phase + '; a second run is refused')
            }
        } elseif ((@($script:StartedState, $script:StoppedState) -ccontains $stageState) -and
            (@('s7_provision', 's7_provisioned') -ccontains $phase)) {
            $step = 'provision'
            $reuse = $true
        } else {
            Throw-NewtonRefusal 'out_of_order' ('a resume plan does not run a stage 7 at ' + $stageState + ' ' + $phase)
        }
    } else {
        if (-not $Request.ContainsKey('odj_bytes')) { Throw-NewtonRefusal 'schema' 'the run of DC2 carries the offline domain join blob' }
        if ($stageState -cne '') {
            Throw-NewtonRefusal 'out_of_order' ('the stage is in flight at ' + $stageState + ' ' + $phase + '; a second run is refused')
        }
        $step = 'join'
    }
    foreach ($one in @('s7-provision', 's7-install', 's7-read')) {
        if (($role -ceq 'dc1') -and (Test-NewtonPasswordTaskRunning -Op $one)) {
            Throw-NewtonRefusal 'out_of_order' ('the password task NewtonBuild-' + $one + ' of the stage still runs from an earlier request')
        }
    }
    $values = Get-NewtonReplicaValues -Plan $Plan -Role $role -Request $Request -Reuse $reuse
    $nbf = [int64]$Request['nbf']
    $boot = Format-NewtonBootTime (Get-NewtonBootTime)
    $op = 's7-' + $step
    $started = @{ provision = 's7_provision'; install = 's7_install'; read = 's7_read'; join = 's7_join' }[$step]
    Clear-NewtonOpResult -Op $op
    $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) -Stage $script:ReplicaStage `
        -State $script:StartedState -Reason '' -Digest $Digest -Checkpoint $Checkpoint -Boot $boot -Checks @() -Phase $started

    $verdict = $null
    $odj = $null
    $secret = $null
    try {
        $wait = Get-NewtonTaskWait -Request $Request
        switch ($step) {
            'provision' {
                try {
                    $verdict = Invoke-NewtonOp -Op $op -Values $values -AsTask $true -NotBefore $nbf -Groups @() -WaitSeconds $wait
                    if ((-not $verdict.ContainsKey('running')) -and [string]::IsNullOrEmpty([string]$verdict['code'])) {
                        $odj = Read-NewtonOdjFile -Path ([string]$values['BlobFile'])
                    }
                } finally {
                    Remove-NewtonOdjFile -Path ([string]$values['BlobFile'])
                }
            }
            'join' {
                # The DSRM secret of DC2 is derived here from DC2's own K
                # and the salt of the build's secrets (open point 71), the
                # one newton-approve shows under DC2, into the DPAPI file DC1's install
                # reads on DC2 and deletes (MEASURED-1.5, stage 7); a join
                # that stops deletes it, and stage 9 deletes a leftover.
                $secretFile = [string]$values['SecretFile']
                $bytes = [byte[]]$Request['odj_bytes']
                try {
                    Write-NewtonOdjFile -Path ([string]$values['BlobFile']) -Bytes $bytes
                    $secret = Get-NewtonDerivedSecret -Key (Get-NewtonKeyBytes) -Digest (Get-NewtonRequestSecrets) -Info $script:DsrmInfo
                    Write-NewtonSecretFile -Path $secretFile -Secret $secret
                    $secret = $null
                    $verdict = Invoke-NewtonOp -Op $op -Values $values -AsTask $false -NotBefore $nbf -Groups @()
                } finally {
                    $secret = $null
                    [Array]::Clear($bytes, 0, $bytes.Length)
                    Remove-NewtonOdjFile -Path ([string]$values['BlobFile'])
                    if (($null -eq $verdict) -or (-not [string]::IsNullOrEmpty([string]$verdict['code']))) {
                        Remove-NewtonSecretFile -Path $secretFile
                    }
                }
            }
            default {
                $verdict = Invoke-NewtonOp -Op $op -Values $values -AsTask $true -NotBefore $nbf -Groups @() -WaitSeconds $wait
            }
        }
    } catch {
        $verdict = New-NewtonErrorVerdict ([string]$_.Exception.Message)
        $odj = $null
    }
    if (($step -ne 'read') -and $verdict.ContainsKey('running') -and [bool]$verdict['running']) {
        # Only the read-back is recorded from its result file by a later
        # status; a provision or an install still running at the end of
        # the wait stops the stage (the owner decides; open point 43).
        $still = New-NewtonVerdict
        foreach ($check in $verdict['checks']) {
            Add-NewtonCheck $still ([string]$check['name']) $false ([string]$check['detail']) 'op_failed'
        }
        $verdict = $still
        $odj = $null
    }
    switch ($step) {
        'join' {
            return (Complete-NewtonTemplateStage -Run $run -Stage $script:ReplicaStage -Digest $Digest -Checkpoint $Checkpoint `
                -Boot $boot -Verdict $verdict -Reboot $true -Phase 's7_join')
        }
        'read' {
            return (Complete-NewtonTemplateStage -Run $run -Stage $script:ReplicaStage -Digest $Digest -Checkpoint $Checkpoint `
                -Boot $boot -Verdict $verdict -Reboot $false -Phase 's7_read')
        }
    }
    $checks = @($verdict['checks'].ToArray())
    $code = [string]$verdict['code']
    if (-not [string]::IsNullOrEmpty($code)) {
        $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) -Stage $script:ReplicaStage `
            -State $script:StoppedState -Reason $code -Digest $Digest -Checkpoint $Checkpoint -Boot $boot -Checks $checks -Phase $started
        return (New-NewtonAnswer -Ok $false -Status $script:AnswerStopped -Code $code -Checks $checks)
    }
    $ended = @{ provision = 's7_provisioned'; install = 's7_installed' }[$step]
    $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) -Stage $script:ReplicaStage `
        -State $script:StartedState -Reason '' -Digest $Digest -Checkpoint $Checkpoint -Boot $boot -Checks $checks -Phase $ended
    $answer = New-NewtonAnswer -Ok $true -Status $script:AnswerStarted -Code '' -Checks $checks
    if ($step -ceq 'provision') { $answer['odj'] = $odj }
    $odj = $null
    return $answer
}

function Invoke-NewtonReplicaStatus {
    # DC2's stage 7 after a boot: after the join's, it reads itself a
    # member and waits for the promotion's boot (rebooting, s7_member, no
    # restart: DC1's install restarts it); after the promotion's, it reads
    # itself a DC and rotates its machine password (s7-dc, K16).
    param([hashtable]$Request, $Values, [string]$Digest, [string]$Checkpoint, [string]$Phase)
    $run = [string]$Request['run']
    $nbf = [int64]$Request['nbf']
    $boot = Format-NewtonBootTime (Get-NewtonBootTime)
    $verdict = $null
    $ended = ''
    try {
        if ($Phase -ceq 's7_join') {
            $ended = 's7_member'
            $verdict = Invoke-NewtonOp -Op 's7-member' -Values $Values -AsTask $false -NotBefore $nbf -Groups @()
        } elseif ($Phase -ceq 's7_member') {
            $ended = 's7_dc'
            if (-not (Wait-NewtonDirectory)) {
                $verdict = New-NewtonVerdict
                Add-NewtonCheck $verdict 'directory' $false 'Get-ADDomain did not answer' 'directory_unready'
            } elseif (Test-NewtonPasswordTaskRunning -Op 's7-dc') {
                # The SYSTEM task of an earlier request still runs: the
                # stage is in flight, nothing runs and nothing is written.
                # The status after the task ends reads its result file.
                $check = [ordered]@{ name = 's7-dc'; ok = $true
                    detail = 'the SYSTEM task NewtonBuild-s7-dc of an earlier request still runs; the stage is in progress' }
                return (New-NewtonAnswer -Ok $true -Status $script:AnswerStarted -Code '' -Checks @($check))
            } else {
                # DC2's own read runs in the SYSTEM task (the maintainer's
                # ruling, 2026-11-23): the helper's key login holds no
                # network credentials, and dcdiag's KnowsOfRoleHolders and
                # RidManager fail under it.  The status request waits at
                # most the task wait and does not hold the session for the
                # whole op.
                #
                # The entry of the op is written before it runs: a session
                # that drops while the task runs leaves the stage in
                # flight, and the status after the task ends reads the
                # result file of the op instead of starting a second task.
                $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) -Stage $script:ReplicaStage `
                    -State $script:StartedState -Reason '' -Digest $Digest -Checkpoint $Checkpoint -Boot $boot `
                    -Checks @() -Phase 's7_dc'
                $wait = Get-NewtonTaskWait -Request $Request
                $verdict = Invoke-NewtonOp -Op 's7-dc' -Values $Values -AsTask $true -AsSystem `
                    -NotBefore $nbf -Groups @() -WaitSeconds $wait
                if ($verdict.ContainsKey('running') -and [bool]$verdict['running']) {
                    # The op runs in its task and outlived the wait: the
                    # stage is in flight, with no terminal entry.  A later
                    # status reads the result file of the op.
                    return (New-NewtonAnswer -Ok $true -Status $script:AnswerStarted -Code '' -Checks @($verdict['checks'].ToArray()))
                }
            }
        } else {
            Throw-NewtonRefusal 'schema' ('stage 7 has no post-boot template at ' + $Phase)
        }
    } catch {
        if ([string]::IsNullOrEmpty($ended)) { throw }
        $verdict = New-NewtonErrorVerdict ([string]$_.Exception.Message)
    }
    $checks = @($verdict['checks'].ToArray())
    $code = [string]$verdict['code']
    if ((-not [string]::IsNullOrEmpty($code)) -or ($ended -ceq 's7_dc')) {
        return (Complete-NewtonTemplateStage -Run $run -Stage $script:ReplicaStage -Digest $Digest -Checkpoint $Checkpoint `
            -Boot $boot -Verdict $verdict -Reboot $false -Phase $ended)
    }
    $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) -Stage $script:ReplicaStage `
        -State $script:RebootingState -Reason '' -Digest $Digest -Checkpoint $Checkpoint -Boot $boot -Checks $checks -Phase $ended
    return (New-NewtonAnswer -Ok $true -Status $script:AnswerRebooting -Code '' -Checks $checks)
}

function Read-NewtonInstalledWriteHelper {
    # The bytes of the write helper the bootstrap installed, checked first:
    # a file that is missing stops write_helper_missing and one whose sha256
    # is not the plan's stops write_helper_mismatch, each before any op or
    # journal entry and with the one next step (the bootstrap again).
    param([string]$Sha)
    $path = [string](Join-Path (Get-NewtonInstallRoot) $script:WriteHelperFileName)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Throw-NewtonRefusal 'write_helper_missing' ('the bootstrap installed no write helper ' + $script:WriteHelperFileName + '; ' + $script:WriteHelperNextStep)
    }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ((Get-NewtonSha256Hex $bytes) -cne $Sha) {
        Throw-NewtonRefusal 'write_helper_mismatch' ('the sha256 of the installed write helper ' + $script:WriteHelperFileName + ' is not the plan''s; ' + $script:WriteHelperNextStep)
    }
    return ,$bytes
}

function Test-NewtonOpsTasksRunning {
    # A password task of stage 8, or its sshd restart task, still runs from
    # an earlier request.
    foreach ($one in @('s8-audit', 's8-ops', 's8-read')) {
        if (Test-NewtonPasswordTaskRunning -Op $one) { return ('the password task NewtonBuild-' + $one) }
    }
    if (Test-NewtonSshdRestartRunning) { return ('the task ' + $script:SshdRestartTaskName) }
    return ''
}

function Test-NewtonSshdRestartRunning {
    # True when the sshd restart task of stage 8 is running, or queued.
    $task = Get-ScheduledTask -TaskName $script:SshdRestartTaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $false }
    return (@('Running', 'Queued') -contains [string]$task.State)
}

function Invoke-NewtonOpsRun {
    # The run of stage 8: the write helper the bootstrap installed must be
    # there and hash to the plan's; the two filled setups run in the
    # password task, then the sshd restart task is registered.  The stage
    # stays started (s8_restart) until a status finds the restart's result
    # file and reads stage 8 back.
    param([hashtable]$Request, [hashtable]$Plan, [string]$Digest, [string]$Checkpoint)
    $run = [string]$Request['run']
    if (-not (Test-NewtonWindowsHost)) {
        Throw-NewtonRefusal 'schema' 'the stage templates of this host are not built yet: they run only under Windows'
    }
    $values = Get-NewtonOpsValues -Plan $Plan -Role ([string]$Request['role'])
    $helper = Read-NewtonInstalledWriteHelper -Sha ([string]$values['WriteHelperSha'])
    $busy = Test-NewtonOpsTasksRunning
    if (-not [string]::IsNullOrEmpty($busy)) {
        Throw-NewtonRefusal 'out_of_order' ($busy + ' of the stage still runs from an earlier request')
    }
    $texts = [ordered]@{}
    foreach ($op in $script:SetupTemplates.Keys) {
        $texts[$op] = Get-NewtonSetupText -Op $op -Values $values -Helper $helper
    }
    foreach ($op in @('s8-audit', 's8-ops', 's8-restart', $script:SshdRestartOp, 's8-read')) { Clear-NewtonOpResult -Op $op }
    $nbf = [int64]$Request['nbf']
    $boot = Format-NewtonBootTime (Get-NewtonBootTime)
    $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) -Stage $script:OpsStage `
        -State $script:StartedState -Reason '' -Digest $Digest -Checkpoint $Checkpoint -Boot $boot -Checks @() -Phase 's8_setup'
    $verdict = New-NewtonVerdict
    try {
        $wait = Get-NewtonTaskWait -Request $Request
        foreach ($op in $script:SetupTemplates.Keys) {
            $path = [string]$script:SetupScripts[$op]
            $text = [string]$texts[$op]
            Write-NewtonSetupScript -Path $path -Text $text
            $values['SetupScript'] = $path
            $values['SetupSha'] = Get-NewtonSha256Hex ((New-Object System.Text.UTF8Encoding $true).GetPreamble() + (New-Object System.Text.UTF8Encoding $false).GetBytes($text))
            $one = Invoke-NewtonOp -Op $op -Values $values -AsTask $true -NotBefore $nbf -Groups @() -WaitSeconds $wait
            if ($one.ContainsKey('running')) {
                # A setup still running at the end of its wait stops the
                # stage; it is not recorded later (DESIGN-1.5, the task 8
                # open points).
                Add-NewtonCheck $verdict $op $false 'the setup still runs in its password task' 'op_failed'
                break
            }
            $verdict['checks'].AddRange($one['checks'])
            if (-not [string]::IsNullOrEmpty([string]$one['code'])) { $verdict['code'] = [string]$one['code']; break }
        }
        if ([string]::IsNullOrEmpty([string]$verdict['code'])) {
            $restart = Get-NewtonSshdRestartScript
            $values['RestartB64'] = [Convert]::ToBase64String((New-Object System.Text.UTF8Encoding $false).GetBytes($restart))
            $values['RestartScript'] = $script:SshdRestartScriptPath
            $values['RestartTask'] = $script:SshdRestartTaskName
            $one = Invoke-NewtonOp -Op 's8-restart' -Values $values -AsTask $false -NotBefore $nbf -Groups @()
            $verdict['checks'].AddRange($one['checks'])
            if (-not [string]::IsNullOrEmpty([string]$one['code'])) { $verdict['code'] = [string]$one['code'] }
        }
    } catch {
        $verdict = New-NewtonErrorVerdict ([string]$_.Exception.Message)
    }
    $checks = @($verdict['checks'].ToArray())
    $code = [string]$verdict['code']
    if (-not [string]::IsNullOrEmpty($code)) {
        $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) -Stage $script:OpsStage `
            -State $script:StoppedState -Reason $code -Digest $Digest -Checkpoint $Checkpoint -Boot $boot -Checks $checks -Phase 's8_setup'
        return (New-NewtonAnswer -Ok $false -Status $script:AnswerStopped -Code $code -Checks $checks)
    }
    $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) -Stage $script:OpsStage `
        -State $script:StartedState -Reason '' -Digest $Digest -Checkpoint $Checkpoint -Boot $boot -Checks $checks -Phase 's8_restart'
    return (New-NewtonAnswer -Ok $true -Status $script:AnswerStarted -Code '' -Checks $checks)
}

function Invoke-NewtonOpsStatus {
    # The status of a stage 8 left started.  At s8_restart: while the sshd
    # restart has written no result file it answers started, for at most
    # SshdRestartWaitSeconds after the entry; a restart that failed stops
    # op_failed; one that passed is followed by the read-back, which ends
    # the stage done or stopped readback_failed.  A read-back still running
    # from an earlier status answers started; one that ended is read from
    # its result file.  At s8_setup (a session
    # that dropped while a setup ran) it answers started and records
    # nothing: the setups are not on the status record path.
    param([hashtable]$Request, [hashtable]$Plan, [string]$Digest, [string]$Checkpoint, $State)
    $run = [string]$Request['run']
    $phase = Get-NewtonReplicaPhase $State
    $checks = ConvertTo-NewtonChecks (Get-NewtonField $State['record'] 'checks')
    if ($phase -cne 's8_restart') {
        return (New-NewtonAnswer -Ok $true -Status $script:AnswerStarted -Code '' -Checks $checks)
    }
    if (-not (Test-NewtonStartedUnder -State $State -Digest $Digest)) {
        Throw-NewtonRefusal 'plan_mismatch' 'stage 8 was started under another plan: a status of this plan does not go on with it'
    }
    if (-not (Test-NewtonWindowsHost)) {
        Throw-NewtonRefusal 'schema' 'the stage templates of this host are not built yet: they run only under Windows'
    }
    $boot = Format-NewtonBootTime (Get-NewtonBootTime)
    $restarted = Read-NewtonOpResult -Op $script:SshdRestartOp
    if ($null -eq $restarted) {
        $since = Get-NewtonField $State['record'] 'time'
        if ((Test-NewtonInt $since) -and ((Get-NewtonNow) -le ([int64]$since + $script:SshdRestartWaitSeconds))) {
            return (New-NewtonAnswer -Ok $true -Status $script:AnswerStarted -Code '' -Checks $checks)
        }
        $verdict = New-NewtonVerdict
        Add-NewtonCheck $verdict 'sshd_restart' $false ('the sshd restart wrote no result within ' + [string]$script:SshdRestartWaitSeconds + ' s') 'op_failed'
        return (Complete-NewtonTemplateStage -Run $run -Stage $script:OpsStage -Digest $Digest -Checkpoint $Checkpoint `
            -Boot $boot -Verdict $verdict -Reboot $false -Phase 's8_restart')
    }
    $verdict = Get-NewtonStage8SshdVerdict -Result ([int]$restarted['result']) -Output ([string]$restarted['output'])
    if ([string]::IsNullOrEmpty([string]$verdict['code'])) {
        # A read-back an earlier status started, whose session dropped
        # (review finding 5 of task 8 part E): while its task runs the
        # stage stays started and nothing is recorded; once it ended, its
        # result file (the run of stage 8 cleared any older one) is read
        # and the op is not run again.
        if (Test-NewtonPasswordTaskRunning -Op 's8-read') {
            return (New-NewtonAnswer -Ok $true -Status $script:AnswerStarted -Code '' -Checks $checks)
        }
        try {
            $values = Get-NewtonOpsValues -Plan $Plan -Role ([string]$Request['role'])
            $read = Invoke-NewtonOp -Op 's8-read' -Values $values -AsTask $true -NotBefore ([int64]$Request['nbf']) -Groups @() `
                -WaitSeconds $script:TaskWaitSeconds -FromEarlier
            if ($read.ContainsKey('running')) {
                Add-NewtonCheck $verdict 's8-read' $false 'the read-back did not end in its wait' 'readback_failed'
            } else {
                $verdict['checks'].AddRange($read['checks'])
                if (-not [string]::IsNullOrEmpty([string]$read['code'])) { $verdict['code'] = [string]$read['code'] }
            }
        } catch {
            $verdict = New-NewtonErrorVerdict ([string]$_.Exception.Message)
        }
    }
    return (Complete-NewtonTemplateStage -Run $run -Stage $script:OpsStage -Digest $Digest -Checkpoint $Checkpoint `
        -Boot $boot -Verdict $verdict -Reboot $false -Phase 's8_restart')
}

function Invoke-NewtonRun {
    # The run of a stage: the helper writes the entry of the start, runs
    # the stage and writes the entry of its outcome.
    param([hashtable]$Request, [hashtable]$Plan, [string]$Digest, [string]$Checkpoint, $Entries)
    $run = [string]$Request['run']
    $stage = [string]$Request['stage']
    $boot = Format-NewtonBootTime (Get-NewtonBootTime)

    $state = Get-NewtonStageState -Entries $Entries -Stage $stage
    $stageState = [string]$state['state']
    if ($stageState -eq $script:DoneState) {
        Throw-NewtonRefusal 'already_done' 'the stage is already done'
    }
    $journalDigest = Get-NewtonJournalDigest $Entries
    if (($stage -ceq $script:ReplicaStage) -and [string]::IsNullOrEmpty((Get-NewtonStageTablePath))) {
        return (Invoke-NewtonReplicaRun -Request $Request -Plan $Plan -Digest $Digest -Checkpoint $Checkpoint `
            -Entries $Entries -JournalDigest $journalDigest -State $state)
    }
    if ($journalDigest -ceq $Digest) {
        # The run of this plan is in flight: a stage that started, a
        # stage that waits for a reboot and a stage that stopped may
        # not run again under this plan.  A new plan resumes the run.
        if (($stageState -eq $script:StartedState) -or
            ($stageState -eq $script:RebootingState) -or
            ($stageState -eq $script:StoppedState)) {
            Throw-NewtonRefusal 'out_of_order' 'the stage is in flight; a second run is refused'
        }
    }
    $graph = $Request['graph']
    $next = Get-NewtonNextStage -Graph $graph -Entries $Entries
    if ($stage -cne $next) {
        Throw-NewtonRefusal 'out_of_order' 'the stage is not the next one of the graph'
    }

    # With no fake table, the stage runs its template.  Stage 7 has its own
    # runs (Invoke-NewtonReplicaRun, above) and stage 8 its own
    # (Invoke-NewtonOpsRun); stage 10 is not in the helper, so such a stage
    # runs nothing and writes nothing, the way the checkpoint does.
    # The templates run only under Windows.
    if ([string]::IsNullOrEmpty((Get-NewtonStageTablePath))) {
        if ($stage -ceq $script:OpsStage) {
            return (Invoke-NewtonOpsRun -Request $Request -Plan $Plan -Digest $Digest -Checkpoint $Checkpoint)
        }
        if (-not (Test-NewtonTemplateStage $stage)) {
            Throw-NewtonRefusal 'schema' 'the stage templates are not built yet'
        }
        if (-not (Test-NewtonWindowsHost)) {
            Throw-NewtonRefusal 'schema' 'the stage templates of this host are not built yet: they run only under Windows'
        }
        $values = Get-NewtonStageValues -Plan $Plan -Role ([string]$Request['role'])
        return (Invoke-NewtonTemplateRun -Request $Request -Values $values -Digest $Digest -Checkpoint $Checkpoint -Entries $Entries)
    }

    $table = Get-NewtonStageTable
    $entry = Get-NewtonStageEntry -Table $table -Stage $stage
    $checks = $entry['checks']

    $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) `
        -Stage $stage -State $script:StartedState -Reason '' -Digest $Digest `
        -Checkpoint $Checkpoint -Boot $boot -Checks @()

    if ([bool]$entry['reboot']) {
        $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) `
            -Stage $stage -State $script:RebootingState -Reason '' -Digest $Digest `
            -Checkpoint $Checkpoint -Boot $boot -Checks $checks
        if ([bool]$entry['drop']) { Invoke-NewtonDroppedConnection }
        return (New-NewtonAnswer -Ok $true -Status $script:AnswerRebooting -Code '' -Checks $checks)
    }

    $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) `
        -Stage $stage -State $script:DoneState -Reason '' -Digest $Digest `
        -Checkpoint $Checkpoint -Boot $boot -Checks $checks
    if ([bool]$entry['drop']) { Invoke-NewtonDroppedConnection }
    return (New-NewtonAnswer -Ok $true -Status $script:AnswerDone -Code '' -Checks $checks)
}

function Invoke-NewtonStatus {
    # The status of a stage: the journal answers it, and the stage that
    # waits for a reboot is completed when the boot time has advanced.
    param([hashtable]$Request, [hashtable]$Plan, [string]$Digest, [string]$Checkpoint, $Entries)
    $run = [string]$Request['run']
    $stage = [string]$Request['stage']
    $state = Get-NewtonStageState -Entries $Entries -Stage $stage

    if ([string]$state['state'] -eq $script:RebootingState) {
        $record = $state['record']
        $before = Get-NewtonBootText $record
        $now = Format-NewtonBootTime (Get-NewtonBootTime)
        if (-not (Test-NewtonBootAdvanced $before $now)) {
            # Stage 7's DC2 waits at s7_member for the boot DC1's install
            # makes: its answer carries the checks of that read, which the
            # runner waits for before the install.
            $waiting = @()
            if ($stage -ceq $script:ReplicaStage) { $waiting = ConvertTo-NewtonChecks (Get-NewtonField $record 'checks') }
            return (New-NewtonAnswer -Ok $true -Status $script:AnswerRebooting -Code '' -Checks $waiting)
        }
        if (($stage -ceq $script:ReplicaStage) -and [string]::IsNullOrEmpty((Get-NewtonStageTablePath))) {
            if (-not (Test-NewtonWindowsHost)) {
                Throw-NewtonRefusal 'schema' 'the stage templates of this host are not built yet: they run only under Windows'
            }
            if (-not (Test-NewtonStartedUnder -State $state -Digest $Digest)) {
                Throw-NewtonRefusal 'plan_mismatch' 'stage 7 waits for a boot under another plan: a status of this plan does not go on with it'
            }
            $values = Get-NewtonReplicaValues -Plan $Plan -Role ([string]$Request['role']) -Request $Request -Reuse $false
            return (Invoke-NewtonReplicaStatus -Request $Request -Values $values -Digest $Digest -Checkpoint $Checkpoint `
                -Phase (Get-NewtonReplicaPhase $state))
        }
        # With no fake table, the stage's own template does the post-boot
        # work (stage 7's DC2: Invoke-NewtonReplicaStatus, above).  A stage
        # with no template completes nothing.
        if ([string]::IsNullOrEmpty((Get-NewtonStageTablePath))) {
            if (-not (Test-NewtonTemplateStage $stage)) {
                Throw-NewtonRefusal 'schema' 'the stage templates are not built yet'
            }
            if (-not (Test-NewtonWindowsHost)) {
                Throw-NewtonRefusal 'schema' 'the stage templates of this host are not built yet: they run only under Windows'
            }
            $values = Get-NewtonStageValues -Plan $Plan -Role ([string]$Request['role'])
            return (Invoke-NewtonTemplateStatus -Request $Request -Values $values -Digest $Digest `
                -Checkpoint $Checkpoint -Entries $Entries)
        }
        $table = Get-NewtonStageTable
        $entry = Get-NewtonStageEntry -Table $table -Stage $stage
        $checks = $entry['checks']
        $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) `
            -Stage $stage -State $script:DoneState -Reason '' -Digest $Digest `
            -Checkpoint $Checkpoint -Boot $now -Checks $checks
        return (New-NewtonAnswer -Ok $true -Status $script:AnswerDone -Code '' -Checks $checks)
    }

    # A template stage left started: the session that ran it dropped, or
    # its password task outlived the wait.  The op's own result file is
    # the outcome of the stage, and the status request records it, under
    # the plan the stage started under only.
    # A resume plan's status over the run plan's started entry is refused:
    # its own run reads the role (stage 2) before anything acts on the
    # earlier op's result.
    # Stage 8 left started: the sshd restart and the read-back after it
    # (Invoke-NewtonOpsStatus).
    if (($stage -ceq $script:OpsStage) -and ([string]$state['state'] -eq $script:StartedState) -and
        [string]::IsNullOrEmpty((Get-NewtonStageTablePath))) {
        return (Invoke-NewtonOpsStatus -Request $Request -Plan $Plan -Digest $Digest -Checkpoint $Checkpoint -State $state)
    }
    if (Test-NewtonRecordStage -Stage $stage -State $state) {
        if (-not (Test-NewtonStartedUnder -State $state -Digest $Digest)) {
            Throw-NewtonRefusal 'plan_mismatch' 'the stage was started under another plan: a status of this plan does not record it; this plan runs the stage itself'
        }
        if ($stage -ceq $script:ReplicaStage) {
            $values = Get-NewtonReplicaValues -Plan $Plan -Role ([string]$Request['role']) -Request $Request -Reuse $false
        } else {
            $values = Get-NewtonStageValues -Plan $Plan -Role ([string]$Request['role'])
        }
        return (Invoke-NewtonTemplateRecord -Request $Request -Values $values -Digest $Digest `
            -Checkpoint $Checkpoint -Phase (Get-NewtonReplicaPhase $state) `
            -PastBound:([bool]$Request['past_bound']))
    }

    $checks = @()
    if ($null -ne $state['record']) {
        $checks = ConvertTo-NewtonChecks (Get-NewtonField $state['record'] 'checks')
    }
    $status = $script:AnswerPending
    switch ([string]$state['state']) {
        $script:StartedState { $status = $script:AnswerStarted }
        $script:DoneState { $status = $script:AnswerDone }
        $script:StoppedState { $status = $script:AnswerStopped }
    }
    return (New-NewtonAnswer -Ok $true -Status $status -Code '' -Checks $checks)
}

function Get-NewtonCompletions {
    # The recorded completion of every stage of the graph that is done:
    # the time of its last done entry, the helper's clock, a UTC second.
    # A stage with no done entry, or whose time is not an integer, has
    # none.
    param($Entries, [string[]]$Graph)
    $completed = [ordered]@{}
    foreach ($stage in $Graph) {
        $time = $null
        foreach ($entry in $Entries) {
            $one = $entry['record']
            if ([string](Get-NewtonField $one 'stage') -cne $stage) { continue }
            if ([string](Get-NewtonField $one 'state') -ne $script:DoneState) { continue }
            $value = Get-NewtonField $one 'time'
            if (Test-NewtonInt $value) { $time = [int64]$value } else { $time = $null }
        }
        if ($null -ne $time) { $completed[$stage] = $time }
    }
    return $completed
}

function Test-NewtonBootAdvanced {
    # True when the server booted after the boot time of the journal.
    param([string]$Before, [string]$Now)
    if ([string]::IsNullOrEmpty($Before)) { return $false }
    if ([string]::IsNullOrEmpty($Now)) { return $false }
    $culture = [Globalization.CultureInfo]::InvariantCulture
    $styles = [Globalization.DateTimeStyles]::RoundtripKind
    $first = [DateTime]::MinValue
    $second = [DateTime]::MinValue
    if (-not [DateTime]::TryParse($Before, $culture, $styles, [ref]$first)) { return $false }
    if (-not [DateTime]::TryParse($Now, $culture, $styles, [ref]$second)) { return $false }
    return ($second.ToUniversalTime() -gt $first.ToUniversalTime())
}

# ---------------------------------------------------------------------------
# the request, checked
# ---------------------------------------------------------------------------

function Invoke-NewtonAction {
    # The whole of one request: the plan, the token, the order and the
    # action.
    param([hashtable]$Request)

    $run = [string]$Request['run']
    $stage = [string]$Request['stage']
    $action = [string]$Request['action']
    $nbf = [int64]$Request['nbf']
    $exp = [int64]$Request['exp']
    $now = Get-NewtonNow

    $planBytes = [byte[]]$Request['plan_bytes']
    $plan = ConvertFrom-NewtonPlanBytes $planBytes
    $digest = Get-NewtonPlanDigest $planBytes

    # The kinds and the graphs of the plan are the ones of the design:
    # the signed bytes of a plan cannot say otherwise.
    Test-NewtonDesignPlan $plan
    $script:SecretsDigest = Get-NewtonSecretsDigest -Plan $plan -Digest $digest

    $device = Get-NewtonDeviceName
    if ([string]::IsNullOrEmpty($device)) {
        Throw-NewtonRefusal 'schema' 'the device of this server is not known'
    }
    $role = Get-NewtonPlanRole -Plan $plan -Device $device
    $graph = Get-NewtonPlanGraph -Plan $plan -Role $role
    $kind = Get-NewtonDesignKind -Stage $stage

    # The lock of the journal of the server: one request at a time, from
    # here until the answer is written.
    Enter-NewtonJournalLock

    $entries = Get-NewtonJournalEntries $run

    # One run per server: the journal of the server holds the entries of
    # one run, and a resume keeps the same run id.  An entry of another
    # run is a second build, and nothing is written.
    foreach ($entry in $entries) {
        if ([string]$entry['run'] -cne $run) {
            Throw-NewtonRefusal 'plan_mismatch' 'the journal of the server holds the entries of another run'
        }
    }

    # The stage is a stage of the graph of this server: a stage of
    # another server is not next in this one.
    $inGraph = $false
    foreach ($one in $graph) {
        if ($one -ceq $stage) { $inGraph = $true; break }
    }
    if (-not $inGraph) {
        Throw-NewtonRefusal 'out_of_order' 'the stage is not in the graph of this server'
    }

    # The token of the request: the plan token for a read, a reversible
    # or the final stage (stage 9, the maintainer, 2026-11-13: the plan approval
    # covers it, never a stage token), the token of the stage digest for
    # an irreversible one, and the plan token for a checkpoint.  The
    # kind is the kind of the design, never the kind of the plan bytes.
    $checkpoint = ''
    $tokenDigest = $digest
    if ($action -eq 'read') {
        # A DC read is taken for the checkpoint of a stage whose design
        # checkpoint is a DC one on this server, under the plan token.
        if (-not (Test-NewtonDcReadStage -Role $role -Stage $stage)) {
            Throw-NewtonRefusal 'schema' 'the stage takes no DC checkpoint on this server'
        }
    } elseif ($action -ne 'checkpoint') {
        if ($kind -eq $script:IrreversibleKind) {
            $checkpoint = Get-NewtonCheckpointId -Entries $entries -Stage $stage -Digest $digest
            if ([string]::IsNullOrEmpty($checkpoint)) {
                # A plan of another build holds no checkpoint here: it is
                # plan_mismatch, not a stage with no checkpoint.  The
                # check stays after the token for every other request,
                # so one changed byte with the old token is bad_token.
                Assert-NewtonPlanOfRun -Plan $plan -Digest $digest -Graph $graph -Entries $entries
                Throw-NewtonRefusal 'schema' 'the stage has no checkpoint to bind its token to'
            }
            $tokenDigest = Get-NewtonStageDigest -PlanDigest $digest -Stage $stage -CheckpointId $checkpoint
        } elseif (($kind -ne $script:ReadKind) -and ($kind -ne $script:ReversibleKind) -and ($kind -ne $script:FinalKind)) {
            Throw-NewtonRefusal 'schema' 'the kind of the stage is not one of the kinds of the design'
        }
    }
    $key = Get-NewtonKeyBytes
    $expected = Get-NewtonToken -Key $key -Digest $tokenDigest -NotBefore $nbf -NotAfter $exp
    if (-not (Test-NewtonConstantTime $expected ([string]$Request['token']))) {
        Throw-NewtonRefusal 'bad_token' 'the token is not the token of the plan'
    }

    # The plan of the request and the plan of the run.  The check is
    # before the window of the token, so a plan of another build never
    # writes to the journal of this one.
    $journalDigest = Get-NewtonJournalDigest $entries
    Assert-NewtonPlanOfRun -Plan $plan -Digest $digest -Graph $graph -Entries $entries

    # The window of the token.  A stage that waits for a reboot may be
    # completed until the EXP of its token plus the grace; every other
    # request needs a token that is open now.
    # A template stage left started is recorded by a status request until
    # the same EXP plus the grace (it records what already happened and
    # runs no op), and after it as Invoke-NewtonTemplateRecord -PastBound
    # says, so its journal never stays started once its task is over.
    $grace = $false
    $rebooting = $false
    $recording = $false
    if ($action -eq 'status') {
        $state = Get-NewtonStageState -Entries $entries -Stage $stage
        if ([string]$state['state'] -eq $script:RebootingState) {
            $rebooting = $true
            $record = $state['record']
            $before = Get-NewtonBootText $record
            if (Test-NewtonBootAdvanced $before (Format-NewtonBootTime (Get-NewtonBootTime))) {
                $grace = $true
            }
        } elseif ((Test-NewtonRecordStage -Stage $stage -State $state) -and
            (Test-NewtonStartedUnder -State $state -Digest $digest)) {
            $recording = $true
        }
    }
    $Request['past_bound'] = $false
    $limit = $exp
    if ($grace -or $recording) { $limit = $exp + $script:PostBootGraceSeconds }
    if (($now -gt $limit) -and $recording) {
        # Past the bound the status still records, -PastBound.
        $Request['past_bound'] = $true
    } elseif ($now -gt $limit) {
        if ($rebooting -and ($now -gt ($exp + $script:PostBootGraceSeconds))) {
            # The stage waits for a reboot and the grace of its token is
            # over, whether the server came back or not: the stage is
            # stopped and it needs a new token.  The entry holds the
            # digest of the run, not the one of the request.
            $null = Add-NewtonJournalEntry -Run $run -Seq (Get-NewtonNextSeq -Run $run) `
                -Stage $stage -State $script:StoppedState -Reason $script:GracePassedReason `
                -Digest $journalDigest -Checkpoint $checkpoint `
                -Boot (Format-NewtonBootTime (Get-NewtonBootTime)) -Checks @()
        }
        Throw-NewtonRefusal 'expired' 'the window of the token has passed'
    }
    if ($now -lt $nbf) {
        Throw-NewtonRefusal 'expired' 'the window of the token has not opened'
    }

    $Request['graph'] = $graph
    $Request['role'] = $role

    if ($action -eq 'checkpoint') {
        return (Invoke-NewtonCheckpoint -Request $Request -Plan $plan -Digest $digest -Entries $entries)
    }
    if ($action -eq 'read') {
        return (Invoke-NewtonDcRead -Request $Request -Digest $digest -Entries $entries)
    }
    if ($action -eq 'status') {
        $answer = Invoke-NewtonStatus -Request $Request -Plan $plan -Digest $digest -Checkpoint $checkpoint -Entries $entries
        # Each stage's recorded completion, from the journal as it is now
        # (the status may just have written one): the runner and the stage
        # approval take not_before from it (DESIGN-1.5 "Checkpoints").
        $now = Get-NewtonJournalEntries $run
        $answer['completed'] = Get-NewtonCompletions -Entries $now -Graph $graph
        # Each stage's checkpoint of this plan, id and name: a runner that
        # was killed after the helper recorded one verifies it again rather
        # than take a second (F1 of the part C triage of task 8).
        $answer['checkpoints'] = Get-NewtonHeldCheckpoints -Entries $now -Graph $graph -Digest $digest
        return $answer
    }
    return (Invoke-NewtonRun -Request $Request -Plan $plan -Digest $digest -Checkpoint $checkpoint -Entries $entries)
}

function Invoke-NewtonBuild {
    # One request, read on stdin: the whole flow.
    if ((Test-NewtonOverride) -and (Test-NewtonSshSession)) {
        Throw-NewtonRefusal 'schema' 'the helper takes no argument over SSH'
    }
    $raw = Read-NewtonStdin
    $request = ConvertFrom-NewtonRequest $raw
    return (Invoke-NewtonAction -Request $request)
}

# ---------------------------------------------------------------------------
# the main body
# ---------------------------------------------------------------------------

if ($MyInvocation.InvocationName -ne '.') {
    $response = $null
    try {
        $response = Invoke-NewtonBuild
    } catch {
        # The reason of the refusal goes to stderr; the answer of the
        # process is the one JSON object on stdout.
        [Console]::Error.WriteLine('newton: ' + [string]$_.Exception.Message)
        $response = New-NewtonAnswer -Ok $false -Status $script:AnswerRefused `
            -Code (Get-NewtonRefusalCode $_) -Checks @()
    }
    $json = $response | ConvertTo-Json -Depth 8 -Compress
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::Out.Write($json + "`n")
    Exit-NewtonJournalLock
    exit 0
}
