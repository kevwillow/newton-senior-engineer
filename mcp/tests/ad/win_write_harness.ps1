# The harness of the Windows write helper tests.
#
# One pwsh process runs this script: it dot-sources write.ps1, puts the fake
# adapters of win_write_fake.ps1 in the test seams of the helper and answers
# the cases of the JSON file it is given.  The answer of every case is one
# JSON object on stdout.
#
#     pwsh -NoProfile -File win_write_harness.ps1 <cases.json>
#
# A case holds one request or a list of them.  Every request of a case runs
# against the same install directory and the same fake directory, so a case
# can show a replay, a sweep or an undo.

param([Parameter(Mandatory = $true)][string]$CasesPath)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $PSCommandPath
$mcpRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $here 'win_write_fake.ps1')
. (Join-Path $mcpRoot 'newton_mcp/ad/collector/write.ps1')

# A case may trace every call of the undo of a record ('undo-record <txid>'
# in the call log), so a test can see that a guard before it held, even
# where the undo itself would change nothing.
$script:OriginalUndoRecord = ${function:Invoke-NewtonUndoRecord}
$script:TraceUndoRecord = $null
function Invoke-NewtonUndoRecord {
    param([string]$Path, $Record, $Adapter)
    if ($null -ne $script:TraceUndoRecord) {
        [void]$script:TraceUndoRecord.Add('undo-record ' + [string]$Record.txid)
    }
    return (& $script:OriginalUndoRecord -Path $Path -Record $Record -Adapter $Adapter)
}

# A case may make the readability test of the failed-write handler throw
# once ('throw_in_live_readable'), so a test can see what a throw from
# inside that handler leaves behind.
$script:OriginalLiveReadable = ${function:Test-NewtonLiveReadable}
$script:ThrowLiveReadable = $false
function Test-NewtonLiveReadable {
    param([string]$Verb, $Live)
    if ($script:ThrowLiveReadable) {
        $script:ThrowLiveReadable = $false
        throw 'the readability test threw'
    }
    return (& $script:OriginalLiveReadable -Verb $Verb -Live $Live)
}

function ConvertTo-CaseHashtable {
    # The case of the JSON file as hashtables: the fake reads them by key.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $table = @{}
        foreach ($property in $Value.PSObject.Properties) {
            $table[$property.Name] = ConvertTo-CaseHashtable $property.Value
        }
        return $table
    }
    if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
        $list = @()
        foreach ($item in $Value) { $list += (ConvertTo-CaseHashtable $item) }
        return ,$list
    }
    return $Value
}

function Get-CaseField {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    foreach ($property in $Object.PSObject.Properties) {
        if ($property.Name -ceq $Name) { return $property.Value }
    }
    return $Default
}

function New-CaseDirectory {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('newton-win-write-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $root -Force
    return $root
}

function Get-CaseFiles {
    param([string]$Root)
    $files = @{}
    $tx = Join-Path $Root 'tx'
    if (-not (Test-Path -LiteralPath $tx)) { return $files }
    foreach ($file in @(Get-ChildItem -LiteralPath $tx -File -ErrorAction SilentlyContinue)) {
        if ($file.Name -eq '.lock') { continue }
        try {
            $files[$file.Name] = [System.IO.File]::ReadAllText($file.FullName)
        } catch {
            $files[$file.Name] = ''
        }
    }
    return $files
}

function Get-CaseObjects {
    param($Fake)
    $objects = @()
    foreach ($key in @($Fake.Objects.Keys)) {
        $object = $Fake.Objects[$key]
        $values = @{}
        if ($null -ne $object['values']) {
            foreach ($name in $object['values'].Keys) {
                $value = $object['values'][$name]
                if ($value -is [byte[]]) {
                    $values[[string]$name] = [System.Convert]::ToBase64String($value)
                    continue
                }
                $texts = @()
                foreach ($item in @($value)) { $texts += [string]$item }
                $values[[string]$name] = $texts
            }
        }
        $objects += ,@{
            dn = [string]$object['dn']
            guid = [string]$object['guid']
            sam = [string]$object['sam']
            values = $values
        }
    }
    return ,$objects
}

function Get-CaseObjectBySam {
    param($Fake, [string]$Sam)
    foreach ($key in @($Fake.Objects.Keys)) {
        $object = $Fake.Objects[$key]
        if ([string]$object['sam'] -ieq $Sam) { return $object }
    }
    throw ('the fake directory holds no ' + $Sam)
}

function Invoke-CaseDirectoryChange {
    # A change another admin makes: 'rename_sam' {from, to}, 'delete_sam',
    # 'hide_attributes' (names the bind cannot read from now on) or
    # 'set_values' {sam or dn, name, values};
    # 'fail_guid_searches_of_sam' makes every later search by the GUID of
    # that account fail.
    param($Request)
    $fake = $script:LdapAdapter
    $rename = Get-CaseField $Request 'rename_sam' $null
    if ($null -ne $rename) {
        $object = Get-CaseObjectBySam $fake ([string](Get-CaseField $rename 'from' ''))
        $to = [string](Get-CaseField $rename 'to' '')
        $upn = $to + '@' + [string]$fake.DnsDomain
        $object['sam'] = $to
        $object['upn'] = $upn
        $object['values']['samaccountname'] = @($to)
        $object['values']['userprincipalname'] = @($upn)
        $fake.Usn = $fake.Usn + 1
        $object['usn_changed'] = $fake.Usn
        $object['values']['usnchanged'] = @([string]$fake.Usn)
    }
    $unreadable = Get-CaseField $Request 'fail_guid_searches_of_sam' $null
    if ($null -ne $unreadable) {
        # every later search by the GUID of that account fails
        $object = Get-CaseObjectBySam $fake ([string]$unreadable)
        $fake.FailGuidSearches = [string]$object['guid']
    }
    $hide = Get-CaseField $Request 'hide_attributes' $null
    if ($null -ne $hide) {
        # from now on the bind cannot read these attributes (the fake's
        # Hidden knob)
        $names = @()
        foreach ($name in @($hide)) { $names += ([string]$name).ToLowerInvariant() }
        $fake.Hidden = $names
    }
    $readable = Get-CaseField $Request 'member_readable_by_search' $null
    if ($null -ne $readable) {
        # whether the bind may read member during each of the next searches
        # on member (the fake's MemberReadableBySearch knob)
        $flags = @()
        foreach ($flag in @($readable)) { $flags += [bool]$flag }
        $fake.MemberReadableBySearch = $flags
    }
    $hideOf = Get-CaseField $Request 'hide_attributes_of' $null
    if ($null -ne $hideOf) {
        # from now on the bind cannot read these attributes of one object:
        # {sam, names} or {dn, names}
        $hideDn = [string](Get-CaseField $hideOf 'dn' '')
        if ($hideDn -ne '') {
            $object = $fake.ObjectByDn($hideDn)
        } else {
            $object = Get-CaseObjectBySam $fake ([string](Get-CaseField $hideOf 'sam' ''))
        }
        $object['hidden_attributes'] = @(Get-CaseField $hideOf 'names' @())
    }
    $values = Get-CaseField $Request 'set_values' $null
    if ($null -ne $values) {
        # somebody else writes one attribute of one account: {sam, name, values}
        $dn = [string](Get-CaseField $values 'dn' '')
        if ($dn -ne '') {
            $object = $fake.ObjectByDn($dn)
        } else {
            $object = Get-CaseObjectBySam $fake ([string](Get-CaseField $values 'sam' ''))
        }
        $object['values'][([string](Get-CaseField $values 'name' '')).ToLowerInvariant()] = @(Get-CaseField $values 'values' @())
    }
    $delete = Get-CaseField $Request 'delete_sam' $null
    if ($null -ne $delete) {
        $object = Get-CaseObjectBySam $fake ([string]$delete)
        $fake.Objects.Remove([string]$object['dn'])
    }
}

function Invoke-CaseRequest {
    # One request of a case: the code, the canonical bytes and the answer.
    param($Request, [string]$Key)
    $stage = [string](Get-CaseField $Request 'stage' 'parse')
    $raw = [string](Get-CaseField $Request 'raw' '')
    $result = @{
        stage = $stage
        code = ''
        canonical_b64 = ''
        digest = ''
        token = ''
        response = $null
        error = ''
        stderr = ''
    }
    $originalError = [Console]::Error
    $errorWriter = New-Object System.IO.StringWriter
    [Console]::SetError($errorWriter)
    try {
        try {
            if ($stage -eq 'directory') {
                # Somebody else changes the fake directory between two
                # requests: renames an account (its sAMAccountName and its
                # user principal name, with a new uSNChanged) or deletes it.
                Invoke-CaseDirectoryChange -Request $Request
                $result['code'] = 'ok'
                return $result
            }
            if ($stage -eq 'undo') {
                $txid = [string](Get-CaseField $Request 'undo' '')
                $response = Invoke-NewtonUndoMode -Txid $txid
                $result['code'] = [string]$response['code']
                $result['response'] = $response
                return $result
            }
            $request = $null
            try {
                $request = ConvertFrom-NewtonRequest -Raw $raw
            } catch {
                $result['code'] = Get-NewtonRefusalCode $_
            }
            if ($null -ne $request) {
                if ($request.ContainsKey('risk')) {
                    $bytes = Get-NewtonCanonicalBytes -Request $request
                    $result['canonical_b64'] = [System.Convert]::ToBase64String($bytes)
                    $digest = Get-NewtonDigest -Request $request
                    $result['digest'] = $digest
                    $result['token'] = Get-NewtonToken -Key (ConvertFrom-NewtonHex $Key) -Digest $digest -NotBefore $request['nbf'] -NotAfter $request['exp']
                }
                if ($stage -eq 'write') {
                    $response = Invoke-NewtonRequest -Raw $raw
                    $result['code'] = [string]$response['code']
                    $result['response'] = $response
                } else {
                    $result['code'] = 'ok'
                }
            }
        } catch {
            $result['error'] = $_.Exception.Message
            $result['code'] = Get-NewtonRefusalCode $_
        }
    } finally {
        [Console]::SetError($originalError)
        $result['stderr'] = $errorWriter.ToString()
        $errorWriter.Dispose()
    }
    return $result
}

$document = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($CasesPath))
$cases = @(Get-CaseField $document 'cases' @())
$answers = @()

foreach ($case in $cases) {
    $id = [string](Get-CaseField $case 'id' '')
    $root = New-CaseDirectory
    $key = [string](Get-CaseField $case 'key' ('11' * 32))
    $device = [string](Get-CaseField $case 'device' 'lab-win')
    $now = Get-CaseField $case 'now' 1800000000

    [System.IO.File]::WriteAllText((Join-Path $root 'approval.key'), ($key + "`n"))
    [System.IO.File]::WriteAllText((Join-Path $root 'device.txt'), ($device + "`n"))
    $null = New-Item -ItemType Directory -Path (Join-Path $root 'tx') -Force

    # A case may seed the transaction store with legacy, numbered or
    # interrupted-write files.  The helper must decide which names are
    # records; the harness only writes the exact bytes the case names.
    $storeFiles = Get-CaseField $case 'store_files' $null
    if ($null -ne $storeFiles) {
        foreach ($property in $storeFiles.PSObject.Properties) {
            [System.IO.File]::WriteAllText(
                (Join-Path (Join-Path $root 'tx') $property.Name),
                [string]$property.Value
            )
        }
    }

    # a case may put a directory where the record of a transaction goes, so
    # that the store fails in a way that is not a replay.
    $blocked = Get-CaseField $case 'record_is_directory' $null
    if ($null -ne $blocked) {
        $null = New-Item -ItemType Directory -Path (Join-Path (Join-Path $root 'tx') ([string]$blocked + '.0.json')) -Force
    }
    # a case may name the exact record file that is a directory: the
    # append of a generation of a transaction, for instance.
    $blockedFile = Get-CaseField $case 'record_is_directory_file' $null
    if ($null -ne $blockedFile) {
        $null = New-Item -ItemType Directory -Path (Join-Path (Join-Path $root 'tx') ([string]$blockedFile)) -Force
    }

    $config = ConvertTo-CaseHashtable (Get-CaseField $case 'ldap' $null)
    if ($null -eq $config) { $config = @{} }
    if (-not $config.ContainsKey('domain_dn')) { $config['domain_dn'] = 'DC=win,DC=newton,DC=test' }
    if (-not $config.ContainsKey('service_name')) { $config['service_name'] = 'WINDC1.win.newton.test' }
    if (-not $config.ContainsKey('dns_domain')) { $config['dns_domain'] = 'win.newton.test' }

    $script:InstallRoot = $root
    $script:WriteAccountSam = [string](Get-CaseField $case 'write_account' 'newton-ops')
    $script:DeviceOverride = ''
    $script:KeyOverride = ''
    $script:LockTimeoutSeconds = 30
    $lockTimeout = Get-CaseField $case 'lock_timeout' $null
    if ($null -ne $lockTimeout) { $script:LockTimeoutSeconds = [int]$lockTimeout }

    $sshConnection = Get-CaseField $case 'ssh_connection' $null
    if ($null -eq $sshConnection) {
        Remove-Item Env:SSH_CONNECTION -ErrorAction SilentlyContinue
    } else {
        $env:SSH_CONNECTION = [string]$sshConnection
    }
    $sshClient = Get-CaseField $case 'ssh_client' $null
    if ($null -eq $sshClient) {
        Remove-Item Env:SSH_CLIENT -ErrorAction SilentlyContinue
    } else {
        $env:SSH_CLIENT = [string]$sshClient
    }

    $calls = New-Object System.Collections.ArrayList
    $script:LdapAdapter = New-NewtonFakeLdap -Config $config -CallLog $calls
    $script:TraceUndoRecord = $null
    if ([bool](Get-CaseField $case 'trace_undo_record' $false)) { $script:TraceUndoRecord = $calls }
    $script:ThrowLiveReadable = [bool](Get-CaseField $case 'throw_in_live_readable' $false)
    $registerError = [bool](Get-CaseField $case 'scheduler_register_error' $false)
    $deleteError = [bool](Get-CaseField $case 'scheduler_delete_error' $false)
    $script:SchedulerAdapter = New-NewtonFakeScheduler -CallLog $calls -RegisterError $registerError -DeleteError $deleteError
    $collisionPath = ''
    $collisionTxid = Get-CaseField $case 'record_collision' $null
    if ($null -ne $collisionTxid) {
        $collisionPath = Join-Path (Join-Path $root 'tx') ([string]$collisionTxid + '.0.json')
    }
    $readErrorAfter = [int](Get-CaseField $case 'read_error_after_modifies' 0)
    $failOncePath = ''
    $failOnceFile = Get-CaseField $case 'record_create_fails_once' $null
    if ($null -ne $failOnceFile) {
        $failOncePath = Join-Path (Join-Path $root 'tx') ([string]$failOnceFile)
    }
    $flushFailPath = ''
    $flushFailFile = Get-CaseField $case 'record_flush_fails_once' $null
    if ($null -ne $flushFailFile) {
        $flushFailPath = Join-Path (Join-Path $root 'tx') ([string]$flushFailFile)
    }
    $readFailsPath = ''
    $readFailsFile = Get-CaseField $case 'store_reads_fail_once_there' $null
    if ($null -ne $readFailsFile) {
        $readFailsPath = Join-Path (Join-Path $root 'tx') ([string]$readFailsFile)
    }
    $tornPath = ''
    $tornFile = Get-CaseField $case 'record_write_torn_once' $null
    if ($null -ne $tornFile) {
        $tornPath = Join-Path (Join-Path $root 'tx') ([string]$tornFile)
    }
    $readThrowsPath = ''
    $readThrowsFile = Get-CaseField $case 'record_read_throws' $null
    if ($null -ne $readThrowsFile) {
        $readThrowsPath = Join-Path (Join-Path $root 'tx') ([string]$readThrowsFile)
    }
    $script:FileSystemAdapter = New-NewtonFakeFileSystem -LockUnauthorized ([bool](Get-CaseField $case 'lock_unauthorized' $false)) -CreateNewCollisionPath $collisionPath -Ldap $script:LdapAdapter -ReadErrorAfterModifies $readErrorAfter -CreateNewFailOncePath $failOncePath -FlushFailOncePath $flushFailPath -ReadFailsOncePath $readFailsPath -TornWriteOncePath $tornPath -ReadThrowsPath $readThrowsPath -ListThrows ([bool](Get-CaseField $case 'store_list_throws' $false))

    $held = $null
    if ([bool](Get-CaseField $case 'hold_lock' $false)) {
        $held = [System.IO.File]::Open(
            (Join-Path (Join-Path $root 'tx') '.lock'),
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
    }

    $requests = @()
    $listed = Get-CaseField $case 'requests' $null
    if ($null -ne $listed) {
        $requests = @($listed)
    } else {
        $requests = @($case)
    }

    $results = @()
    foreach ($request in $requests) {
        $script:NowOverride = [int64](Get-CaseField $request 'now' $now)
        $results += ,(Invoke-CaseRequest -Request $request -Key $key)
    }

    $log = @()
    foreach ($entry in $script:LdapAdapter.Log) { $log += [string]$entry }
    $schedulerLog = @()
    foreach ($entry in $script:SchedulerAdapter.Log) { $schedulerLog += [string]$entry }
    $fileLog = @()
    foreach ($entry in $script:FileSystemAdapter.Log) { $fileLog += [string]$entry }
    $callLog = @()
    foreach ($entry in $calls) { $callLog += [string]$entry }
    $tasks = @()
    foreach ($name in @($script:SchedulerAdapter.Tasks.Keys)) {
        $tasks += ,@{ name = [string]$name; boundary = [string]$script:SchedulerAdapter.Tasks[$name]['boundary'] }
    }

    $first = $results[0]
    $answers += ,@{
        id = $id
        code = $first['code']
        canonical_b64 = $first['canonical_b64']
        digest = $first['digest']
        token = $first['token']
        response = $first['response']
        results = $results
        calls = $callLog
        log = $log
        scheduler_log = $schedulerLog
        file_log = $fileLog
        tasks = $tasks
        objects = (Get-CaseObjects $script:LdapAdapter)
        files = (Get-CaseFiles $root)
        error = $first['error']
    }

    if ($null -ne $held) { $held.Close() }
    $script:LdapAdapter = $null
    $script:SchedulerAdapter = $null
    $script:FileSystemAdapter = $null
    try {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        $null = $_
    }
}

$json = @{ cases = $answers } | ConvertTo-Json -Depth 16 -Compress
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::Out.Write($json + "`n")
exit 0
