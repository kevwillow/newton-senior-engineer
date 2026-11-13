# Measured-shape probe for win_write_fake.ps1.  It never contacts a host.

param([Parameter(Mandatory = $true)][string]$FakePath)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

. $FakePath

function Get-ProbeResultCode {
    param($ErrorRecord)
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        $responseProperty = $exception.PSObject.Properties['Response']
        if (($null -ne $responseProperty) -and ($null -ne $responseProperty.Value)) {
            return [int]$responseProperty.Value.ResultCode
        }
        $exception = $exception.InnerException
    }
    return 0
}

function Test-ProbeUnauthorized {
    param([scriptblock]$Operation)
    try {
        & $Operation
    } catch {
        $exception = $_.Exception
        while ($null -ne $exception) {
            if ($exception -is [System.UnauthorizedAccessException]) { return $true }
            $exception = $exception.InnerException
        }
    }
    return $false
}

function Invoke-ProbeOldRecordWrite {
    # The exact shape the helper no longer uses: write .new, Replace, then fall back
    # to Delete + Move.  The measured fake must refuse it without changing
    # the existing record.
    param($FileSystem, [string]$Path, [string]$Text)
    $temporary = $Path + '.new'
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $stream = $FileSystem.Open($temporary, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    } finally {
        $stream.Close()
    }
    try {
        $FileSystem.Replace($temporary, $Path, $null)
    } catch {
        if ([System.IO.File]::Exists($Path)) { $FileSystem.DeleteFile($Path) }
        $FileSystem.Move($temporary, $Path)
    }
}

$domainDn = 'DC=win,DC=newton,DC=test'
$accountDn = 'CN=newton-ops,OU=Ops,' + $domainDn
$sourceDn = 'CN=move-me,OU=Users,' + $domainDn
$newParent = 'OU=Ops,' + $domainDn
$config = @{
    domain_dn = $domainDn
    dns_domain = 'win.newton.test'
    service_name = 'WSBXDC1.win.newton.test'
    pdc = $true
    objects = @(
        @{
            dn = $accountDn
            guid = '0a9619ff-8b86-d011-b42d-00c04fc964ff'
            sid = 'S-1-5-21-1-2-3-1100'
            sam = 'newton-ops'
            object_class = @('top', 'person', 'user')
            token_groups = @('S-1-5-21-1-2-3-513')
            delegated = $true
        }
        @{
            dn = $sourceDn
            guid = '6f9619ff-8b86-d011-b42d-00c04fc964ff'
            sid = 'S-1-5-21-1-2-3-1105'
            sam = 'move-me'
            object_class = @('top', 'person', 'user')
            parent = 'OU=Users,' + $domainDn
            delegated = $true
        }
        @{
            dn = 'OU=Users,' + $domainDn
            guid = 'af9619ff-8b86-d011-b42d-00c04fc964ff'
            object_class = @('top', 'organizationalUnit')
            delegated = $true
        }
        @{
            dn = $newParent
            guid = 'bf9619ff-8b86-d011-b42d-00c04fc964ff'
            object_class = @('top', 'organizationalUnit')
            delegated = $true
        }
        @{
            dn = 'CN=a-group,OU=Users,' + $domainDn
            guid = 'cf9619ff-8b86-d011-b42d-00c04fc964ff'
            object_class = @('top', 'group')
            member = @('CN=someone,OU=Users,' + $domainDn)
            delegated = $true
        }
        @{
            # a real DC keeps the case of the name the account was given
            dn = 'CN=Administrator,' + $domainDn
            guid = '3f9619ff-8b86-d011-b42d-00c04fc964ff'
            sid = 'S-1-5-21-1-2-3-500'
            sam = 'Administrator'
            object_class = @('top', 'person', 'user')
            delegated = $true
        }
    )
}

$fake = New-NewtonFakeLdap -Config $config
$result = [ordered]@{}

$entry = @($fake.Search($domainDn, '(sAMAccountName=newton-ops)', 'sub', [string[]]@('sAMAccountName')))[0]
$result['requested_keys'] = @($entry['attrs'].Keys | Sort-Object)
$result['unrequested_sid_present'] = $entry['attrs'].ContainsKey('objectsid')

try {
    $null = $fake.Search('', '(objectClass=*)', 'sub', [string[]]@('objectClass'))
    $result['empty_subtree_code'] = 0
} catch {
    $result['empty_subtree_code'] = Get-ProbeResultCode $_
}

$binary = @($fake.Search($accountDn, '(objectClass=*)', 'base', [string[]]@('objectSid', 'objectGUID', 'tokenGroups')))[0]
$result['sid_is_bytes'] = ($binary['attrs']['objectsid'] -is [byte[]])
$result['guid_is_bytes'] = ($binary['attrs']['objectguid'] -is [byte[]])
$tokenValues = @($binary['attrs']['tokengroups'])
$result['token_count'] = $tokenValues.Count
$result['token_is_bytes'] = (($tokenValues.Count -gt 0) -and ($tokenValues[0] -is [byte[]]))
$subtree = @($fake.Search($domainDn, '(sAMAccountName=newton-ops)', 'sub', [string[]]@('tokenGroups')))[0]
$result['subtree_token_present'] = $subtree['attrs'].ContainsKey('tokengroups')

$root = @($fake.Search('', '(objectClass=*)', 'base', [string[]]@('dsServiceName')))[0]
$ntdsDn = [string]@($root['attrs']['dsservicename'])[0]
$result['ds_service_name'] = $ntdsDn
$ntds = @($fake.Search($ntdsDn, '(objectClass=*)', 'base', [string[]]@('dNSHostName')))[0]
$result['ntds_has_dns'] = $ntds['attrs'].ContainsKey('dnshostname')
$dcOuDn = 'OU=Domain Controllers,' + $domainDn
$dcOu = @($fake.Search($dcOuDn, '(objectClass=*)', 'base', [string[]]@('objectClass', 'parent')))[0]
$result['dc_ou_classes'] = @($dcOu['attrs']['objectclass'])
$result['dc_ou_has_parent'] = $dcOu['attrs'].ContainsKey('parent')

$domain = @($fake.Search($domainDn, '(objectClass=domainDNS)', 'base', [string[]]@('ms-DS-MachineAccountQuota', 'msDS-MachineAccountQuota')))[0]
$result['quota_keys'] = @($domain['attrs'].Keys | Sort-Object)
$head = @($fake.Search($domainDn, '(objectClass=domainDNS)', 'base', [string[]]@('dNSDomainName', 'objectGUID')))[0]
$result['head_dns_keys'] = @($head['attrs'].Keys | Where-Object { $_ -eq 'dnsdomainname' })

try {
    $fake.Modify($sourceDn, 'distinguishedName', @($sourceDn), @('CN=move-me,' + $newParent))
    $result['modify_dn_code'] = 0
} catch {
    $result['modify_dn_code'] = Get-ProbeResultCode $_
}

$fake.ModifyDN($sourceDn, $newParent, 'CN=move-me')
$movedDn = 'CN=move-me,' + $newParent
$result['move_exists'] = ($null -ne $fake.ObjectByDn($movedDn))
try {
    $fake.ModifyDN($sourceDn, $newParent, 'CN=move-me')
    $result['move_again_code'] = 0
} catch {
    $result['move_again_code'] = Get-ProbeResultCode $_
}

# the member filter answers the presence of one member, never the list
$groupDn = 'CN=a-group,OU=Users,' + $domainDn
$memberDn = 'CN=someone,OU=Users,' + $domainDn
$found = @($fake.Search($groupDn, '(member=' + $memberDn + ')', 'base', [string[]]@('objectClass')))
$result['member_filter_found'] = ($found.Count -eq 1)
$absent = @($fake.Search($groupDn, '(member=CN=other,OU=Users,' + $domainDn + ')', 'base', [string[]]@('objectClass')))
$result['member_filter_absent'] = ($absent.Count -eq 0)

# the name of an account is held with the case the directory gave it, and a
# name is found without its case
$mixed = @($fake.Search($domainDn, '(sAMAccountName=administrator)', 'sub', [string[]]@('sAMAccountName')))
$result['mixed_case_found'] = ($mixed.Count -eq 1)
if ($mixed.Count -eq 1) {
    $result['mixed_case_sam'] = [string]@($mixed[0]['attrs']['samaccountname'])[0]
} else {
    $result['mixed_case_sam'] = ''
}

# the measured transaction-store ACL
$fileRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('newton-win-write-fs-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $fileRoot -Force
try {
    $fileSystem = New-NewtonFakeFileSystem
    $existing = Join-Path $fileRoot 'existing.json'
    [System.IO.File]::WriteAllText($existing, 'old')

    $readStream = $fileSystem.Open($existing, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
    try {
        $reader = New-Object System.IO.StreamReader($readStream)
        try { $result['existing_read_text'] = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally {
        $readStream.Dispose()
    }
    $result['existing_write_unauthorized'] = Test-ProbeUnauthorized {
        $stream = $fileSystem.Open($existing, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $stream.Dispose()
    }
    $result['existing_readwrite_unauthorized'] = Test-ProbeUnauthorized {
        $stream = $fileSystem.Open($existing, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $stream.Dispose()
    }

    $created = Join-Path $fileRoot 'created.json'
    $createdStream = $fileSystem.Open($created, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $createdBytes = [System.Text.Encoding]::UTF8.GetBytes('new')
        $createdStream.Write($createdBytes, 0, $createdBytes.Length)
    } finally {
        $createdStream.Dispose()
    }
    $result['create_new_text'] = [System.IO.File]::ReadAllText($created)

    $replaceSource = Join-Path $fileRoot 'replace-source.json'
    [System.IO.File]::WriteAllText($replaceSource, 'source')
    $result['replace_unauthorized'] = Test-ProbeUnauthorized {
        $fileSystem.Replace($replaceSource, $existing, $null)
    }
    $result['delete_unauthorized'] = Test-ProbeUnauthorized {
        $fileSystem.DeleteFile($existing)
    }
    $moveSource = Join-Path $fileRoot 'move-source.json'
    [System.IO.File]::WriteAllText($moveSource, 'source')
    $result['move_unauthorized'] = Test-ProbeUnauthorized {
        $fileSystem.Move($moveSource, (Join-Path $fileRoot 'move-destination.json'))
    }

    $oldRecord = Join-Path $fileRoot 'old-record.json'
    [System.IO.File]::WriteAllText($oldRecord, 'old')
    $result['old_record_write_unauthorized'] = Test-ProbeUnauthorized {
        Invoke-ProbeOldRecordWrite -FileSystem $fileSystem -Path $oldRecord -Text 'replacement'
    }
    $result['old_record_text'] = [System.IO.File]::ReadAllText($oldRecord)
} finally {
    Remove-Item -LiteralPath $fileRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$result | ConvertTo-Json -Depth 8 -Compress

