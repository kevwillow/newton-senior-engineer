Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$script:CollectorVersion = '1.3.0'
$script:ByteLimit = 8388608
$script:DeadlineSeconds = 300
$script:PageSize = 500
$script:ServerTimeLimitSeconds = 30
$script:ByteTotal = 0
$script:AllowedWriteSids = @(
    'S-1-5-32-544'
    'S-1-5-18'
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)
$script:GuidPattern = '^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$'
$script:RegistrySettings = @(
    @{ path = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; name = 'LDAPServerIntegrity' }
    @{ path = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; name = 'LdapEnforceChannelBinding' }
    @{ path = 'SYSTEM\CurrentControlSet\Control\Lsa'; name = 'LmCompatibilityLevel' }
    @{ path = 'SYSTEM\CurrentControlSet\Control\Lsa'; name = 'NoLMHash' }
    @{ path = 'SYSTEM\CurrentControlSet\Control\Lsa'; name = 'RestrictAnonymous' }
    @{ path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; name = 'RestrictSendingNTLMTraffic' }
    @{ path = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; name = 'RestrictReceivingNTLMTraffic' }
    @{ path = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; name = 'RestrictNTLMInDomain' }
    @{ path = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; name = 'FullSecureChannelProtection' }
    @{ path = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; name = 'VulnerableChannelAllowList' }
)

# The seven file names a GPO holds, and the folder each of them sits in
# (SPEC-1.3 section 5).  The name of a file of the SYSVOL is not trusted,
# so the path that the document carries is built from this table and from
# nothing else, as the Samba collector builds it.  Any other file is
# reported as other.xml.
$script:GppFiles = @{
    'groups.xml' = @('Groups', 'Groups.xml')
    'services.xml' = @('Services', 'Services.xml')
    'scheduledtasks.xml' = @('ScheduledTasks', 'ScheduledTasks.xml')
    'datasources.xml' = @('DataSources', 'DataSources.xml')
    'drives.xml' = @('Drives', 'Drives.xml')
    'printers.xml' = @('Printers', 'Printers.xml')
    'registry.xml' = @('Registry', 'Registry.xml')
}
$script:OtherFileName = 'other.xml'
$script:MaxFileBytes = 4194304
$script:MaxEntriesPerDirectory = 10000
$script:MaxDepth = 8

function Write-Fail {
    param([int]$Code, [string]$Message)
    [Console]::Error.WriteLine($Message)
    exit $Code
}

function Get-JsonProperty {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Get-DirectoryProperty {
    param($Object, [string]$Name)
    try {
        $value = $Object.$Name
        if ($null -eq $value) { return '' }
        return [string]$value
    } catch {
        try {
            $property = $Object.PSObject.Properties[$Name]
            if ($null -eq $property) { return '' }
            return [string]$property.Value
        } catch {
            return ''
        }
    }
}

function Get-ComErrorCode {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return $null }
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception -is [System.Runtime.InteropServices.COMException]) {
            $value = [int64]$exception.ErrorCode
            if ($value -lt 0) { $value = $value + 4294967296 }
            return ('0x{0:X8}' -f $value)
        }
        $exception = $exception.InnerException
    }
    return $null
}

function Get-StatusForError {
    param($ErrorRecord)
    if ($null -ne $ErrorRecord) {
        $exception = $ErrorRecord.Exception
        while ($null -ne $exception) {
            if ($exception -is [System.UnauthorizedAccessException]) {
                return ,@{ status = 'denied'; error_code = 'access_denied' }
            }
            if ($exception -is [System.Security.SecurityException]) {
                return ,@{ status = 'denied'; error_code = 'access_denied' }
            }
            if ($exception -is [System.IO.DirectoryNotFoundException]) {
                return ,@{ status = 'unavailable'; error_code = 'no_such_object' }
            }
            if ($exception -is [System.IO.FileNotFoundException]) {
                return ,@{ status = 'unavailable'; error_code = 'no_such_object' }
            }
            $exception = $exception.InnerException
        }
    }
    $code = Get-ComErrorCode $ErrorRecord
    if ($null -ne $code) {
        if ($code -eq '0x80072030') { return ,@{ status = 'unavailable'; error_code = 'no_such_object' } }
        if ($code -eq '0x80070005' -or $code -eq '0x8007202B' -or $code -eq '0x8007202D') {
            return ,@{ status = 'denied'; error_code = 'access_denied' }
        }
        if ($code -eq '0x80072004') { return ,@{ status = 'truncated'; error_code = 'size_limit' } }
        if ($code -eq '0x80072003' -or $code -eq '0x80072024') {
            return ,@{ status = 'truncated'; error_code = 'time_limit' }
        }
        if ($code -eq '0x8007203A') { return ,@{ status = 'unavailable'; error_code = 'server_down' } }
    }
    return ,@{ status = 'error'; error_code = 'other' }
}

function Get-ComLargeInteger {
    param($Value)
    try {
        if ($Value -isnot [System.__ComObject]) { return $null }
        $high = [int64]$Value.HighPart
        $low = [int64]$Value.LowPart
        if ($low -lt 0) { $low = $low + 4294967296 }
        $combined = ($high -shl 32) -bor $low
        return $combined.ToString([Globalization.CultureInfo]::InvariantCulture)
    } catch {
        return $null
    }
}

function ConvertTo-DirectoryValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { return [Convert]::ToBase64String($Value) }
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture) + '.0Z'
    }
    if ($Value -is [bool]) {
        if ($Value) { return 'TRUE' }
        return 'FALSE'
    }
    if ($Value -is [int] -or $Value -is [int64] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64]) {
        return $Value.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        return $Value.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    $comValue = Get-ComLargeInteger $Value
    if ($null -ne $comValue) { return $comValue }
    return [string]$Value
}

function Get-FilterAttributeNames {
    param([string]$Filter)
    $names = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrEmpty($Filter)) { return $names }
    $index = 0
    $length = $Filter.Length
    while ($index -lt $length) {
        $character = $Filter[$index]
        if ($character -eq '(' -or $character -eq ')' -or $character -eq '&' -or $character -eq '|' -or $character -eq '!' -or $character -eq ' ') {
            $index = $index + 1
            continue
        }
        $start = $index
        while ($index -lt $length -and $Filter[$index] -match '[A-Za-z0-9-]') {
            $index = $index + 1
        }
        if ($index -eq $start) {
            $index = $index + 1
            continue
        }
        $name = $Filter.Substring($start, $index - $start)
        while ($index -lt $length -and $Filter[$index] -eq ' ') { $index = $index + 1 }
        $operator = ''
        if ($index + 1 -lt $length) {
            $pair = $Filter.Substring($index, 2)
            if ($pair -eq '>=' -or $pair -eq '<=' -or $pair -eq '~=') {
                $operator = $pair
                $index = $index + 2
            }
        }
        if ($operator -eq '' -and $index -lt $length -and $Filter[$index] -eq '=') {
            $operator = '='
            $index = $index + 1
        }
        if ($operator -ne '') { [void]$names.Add($name.ToLowerInvariant()) }
    }
    return $names
}

function Get-ForbiddenProblem {
    param($Query, $Forbidden)
    foreach ($attribute in @(Get-JsonProperty $Query 'attrs' @())) {
        if ($null -eq $attribute) { continue }
        if ($Forbidden.ContainsKey(([string]$attribute).ToLowerInvariant())) { return 'attribute' }
    }
    foreach ($attribute in @(Get-JsonProperty $Query 'binary' @())) {
        if ($null -eq $attribute) { continue }
        if ($Forbidden.ContainsKey(([string]$attribute).ToLowerInvariant())) { return 'attribute' }
    }
    if (-not [bool](Get-JsonProperty $Query 'presence_only' $false)) {
        $filter = [string](Get-JsonProperty $Query 'filter' '')
        foreach ($name in (Get-FilterAttributeNames $filter)) {
            if ($Forbidden.ContainsKey($name)) { return 'filter' }
        }
    }
    return ''
}

function Test-SafeInstallAcl {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $null
        try {
            $sid = [string]$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            return $false
        }
        if ($script:AllowedWriteSids -contains $sid) { continue }
        if (([int]($rule.FileSystemRights -band $writeMask)) -ne 0) { return $false }
    }
    return $true
}

function Expand-NamingContext {
    param([string]$Template, $Context)
    if ($null -eq $Template) { return '' }
    $result = $Template
    $result = $result.Replace('{domain}', [string]$Context['domain_dn'])
    $result = $result.Replace('{config}', [string]$Context['config_dn'])
    $result = $result.Replace('{schema}', [string]$Context['schema_dn'])
    return $result
}

function Get-RangedPropertyValues {
    param($Result, [string]$AttributeName, [string[]]$RangeKeys)
    $values = New-Object System.Collections.ArrayList
    $pattern = '(?i)^' + [regex]::Escape($AttributeName) + ';range=(\d+)-(\d+|\*)$'
    $next = $null
    $complete = $false
    foreach ($key in $RangeKeys) {
        foreach ($value in @($Result.Properties[$key])) { [void]$values.Add($value) }
        $match = [regex]::Match($key, $pattern)
        if (-not $match.Success) { continue }
        if ($match.Groups[2].Value -eq '*') { $complete = $true; continue }
        $candidate = [int]$match.Groups[2].Value + 1
        if ((-not $complete) -and (($null -eq $next) -or ($candidate -lt $next))) { $next = $candidate }
    }
    if (-not $complete) {
        $searchRoot = [string]$Result.Path
        $guard = 0
        while ($null -ne $next) {
            $guard = $guard + 1
            if ($guard -gt 1000) { break }
            if ([DateTime]::UtcNow -gt $script:DeadlineUtc) { break }
            $found = $null
            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($searchRoot)
                $searcher.Filter = '(objectClass=*)'
                $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                $searcher.PageSize = $script:PageSize
                $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds($script:ServerTimeLimitSeconds)
                [void]$searcher.PropertiesToLoad.Add($AttributeName + ';range=' + $next + '-*')
                $found = $searcher.FindOne()
            } catch {
                $found = $null
            }
            if ($null -eq $found) { break }
            $sawRange = $false
            $last = $false
            $stalled = $false
            foreach ($key in $found.Properties.PropertyNames) {
                if ($key -notlike ($AttributeName + ';range=*')) { continue }
                $sawRange = $true
                foreach ($value in @($found.Properties[$key])) { [void]$values.Add($value) }
                $rangeMatch = [regex]::Match($key, $pattern)
                if (-not $rangeMatch.Success) { $last = $true; continue }
                if ($rangeMatch.Groups[2].Value -eq '*') { $last = $true; continue }
                $candidate = [int]$rangeMatch.Groups[2].Value + 1
                if ($candidate -le $next) { $stalled = $true; continue }
                $next = $candidate
            }
            if ($stalled) { break }
            if (-not $sawRange) { break }
            if ($last) { $complete = $true; $next = $null }
        }
    }
    return ,@{ values = $values.ToArray(); complete = $complete }
}

function New-ResultRow {
    param($Result, $Attributes, [ref]$Truncated, [bool]$WithDescriptor = $false)
    $map = [ordered]@{}
    foreach ($attribute in $Attributes) {
        $name = [string]$attribute
        $exactKey = $null
        $rangeKeys = New-Object System.Collections.ArrayList
        foreach ($candidate in $Result.Properties.PropertyNames) {
            if ($candidate -like ($name + ';range=*')) { [void]$rangeKeys.Add($candidate); continue }
            if ($candidate -eq $name) { $exactKey = $candidate }
        }
        $values = $null
        if ($rangeKeys.Count -gt 0) {
            $ranged = Get-RangedPropertyValues $Result $name $rangeKeys.ToArray()
            if (-not [bool]$ranged['complete']) { $Truncated.Value = $true }
            $values = @($ranged['values'])
        } elseif ($null -ne $exactKey) {
            $values = @($Result.Properties[$exactKey])
        }
        if ($null -eq $values) { continue }
        $encoded = @()
        foreach ($value in $values) {
            $text = ConvertTo-DirectoryValue $value
            if ($null -ne $text) { $encoded += $text }
        }
        if ($encoded.Count -eq 0) { continue }
        $map[$name] = $encoded
    }
    if ($WithDescriptor) {
        $descriptorKey = $null
        foreach ($candidate in $Result.Properties.PropertyNames) {
            if ([string]$candidate -ieq 'ntsecuritydescriptor') { $descriptorKey = $candidate; break }
        }
        if ($null -ne $descriptorKey) {
            $encodedDescriptor = @()
            foreach ($value in @($Result.Properties[$descriptorKey])) {
                $text = ConvertTo-DirectoryValue $value
                if ($null -ne $text) { $encodedDescriptor += $text }
            }
            if ($encodedDescriptor.Count -gt 0) { $map['nTSecurityDescriptor'] = $encodedDescriptor }
        }
    }
    $dn = ''
    foreach ($candidate in $Result.Properties.PropertyNames) {
        if ($candidate -eq 'distinguishedName') {
            $values = @($Result.Properties[$candidate])
            if ($values.Count -gt 0) { $dn = [string]$values[0] }
            break
        }
    }
    if ($dn -eq '') { $dn = [string]$Result.Path }
    return ,[ordered]@{ dn = $dn; a = $map }
}

function Invoke-CollectorQuery {
    param($Query, $Context, [string]$BaseOverride = '')
    $baseTemplate = [string](Get-JsonProperty $Query 'base' '')
    $base = Expand-NamingContext $baseTemplate $Context
    if ($BaseOverride -ne '') { $base = $BaseOverride }
    $filter = Expand-NamingContext ([string](Get-JsonProperty $Query 'filter' '(objectClass=*)')) $Context
    $scopeName = [string](Get-JsonProperty $Query 'scope' 'base')
    $attributes = @(Get-JsonProperty $Query 'attrs' @())
    $needDescriptor = [bool](Get-JsonProperty $Query 'sd' $false)
    $limit = [int](Get-JsonProperty $Query 'limit' 1000)
    $rows = @()
    $status = 'ok'
    $errorCode = ''
    try {
        if ($base.Contains('{') -or $base.Contains('}')) {
            $status = 'error'
            $errorCode = 'other'
        } elseif (($scopeName -ne 'base') -and ($scopeName -ne 'sub')) {
            $status = 'error'
            $errorCode = 'other'
        } else {
            $searchRoot = 'LDAP://' + [string]$Context['dns_host'] + '/' + $base
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($searchRoot)
            $searcher.Filter = $filter
            if ($scopeName -eq 'base') {
                $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
            } else {
                $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            }
            $searcher.PageSize = $script:PageSize
            $searcher.SizeLimit = $limit + 1
            $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds($script:ServerTimeLimitSeconds)
            foreach ($attribute in $attributes) {
                [void]$searcher.PropertiesToLoad.Add([string]$attribute)
            }
            if (-not $searcher.PropertiesToLoad.Contains('distinguishedName')) {
                [void]$searcher.PropertiesToLoad.Add('distinguishedName')
            }
            if ($needDescriptor) {
                [void]$searcher.PropertiesToLoad.Add('nTSecurityDescriptor')
                $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Owner,Dacl'
            }
            $results = $searcher.FindAll()
            $collected = New-Object System.Collections.ArrayList
            foreach ($result in $results) {
                if ($collected.Count -ge $limit) {
                    $status = 'truncated'
                    $errorCode = 'size_limit'
                    break
                }
                $rowTruncated = $false
                $rowTruncatedRef = [ref]$rowTruncated
                $row = New-ResultRow $result $attributes $rowTruncatedRef $needDescriptor
                $rowJson = $row | ConvertTo-Json -Depth 12 -Compress
                $rowBytes = [Text.Encoding]::UTF8.GetByteCount([string]$rowJson)
                if (($script:ByteTotal + $rowBytes) -gt $script:ByteLimit) {
                    $status = 'truncated'
                    $errorCode = 'byte_limit'
                    break
                }
                $script:ByteTotal = $script:ByteTotal + $rowBytes
                [void]$collected.Add($row)
                if ($rowTruncatedRef.Value) {
                    $status = 'truncated'
                    $errorCode = 'size_limit'
                }
            }
            $rows = $collected.ToArray()
        }
    } catch {
        $mapped = Get-StatusForError $_
        $status = [string]$mapped['status']
        $errorCode = [string]$mapped['error_code']
        $rows = @()
    }
    return ,[ordered]@{ status = $status; error_code = $errorCode; rows = $rows }
}

function Get-CollectorIdentity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $name = [string]$identity.Name
    $separator = $name.IndexOf('\')
    if ($separator -ge 0) { $name = $name.Substring($separator + 1) }
    $sid = ''
    try { $sid = [string]$identity.User.Value } catch { $sid = '' }
    $groups = @()
    foreach ($group in $identity.Groups) {
        $value = $null
        try {
            $value = [string]$group.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            $value = $null
        }
        if ($null -eq $value -and ([string]$group.Value) -like 'S-1-*') { $value = [string]$group.Value }
        if ($null -ne $value) { $groups += $value }
    }
    return ,[ordered]@{ user = $name; sid = $sid; token_group_sids = $groups }
}

function ConvertFrom-DomainDn {
    param([string]$DomainDn)
    $labels = New-Object System.Collections.ArrayList
    foreach ($part in ($DomainDn -split ',')) {
        $trimmed = $part.Trim()
        if ($trimmed.Length -gt 3 -and $trimmed.Substring(0, 3).ToUpperInvariant() -eq 'DC=') {
            [void]$labels.Add($trimmed.Substring(3).ToLowerInvariant())
        }
    }
    if ($labels.Count -eq 0) { return '' }
    return ($labels -join '.')
}

function Get-DomainDnsName {
    param([string]$DomainDn)
    try {
        $assembly = [System.Reflection.Assembly]::Load('System.DirectoryServices.ActiveDirectory')
        $domainType = $assembly.GetType('System.DirectoryServices.ActiveDirectory.Domain')
        if ($null -eq $domainType) { return '' }
        $domainObject = $domainType.GetMethod('GetCurrentDomain').Invoke($null, @())
        if ($null -eq $domainObject) { return '' }
        return [string]$domainType.GetProperty('Name').GetValue($domainObject, $null)
    } catch {
        return (ConvertFrom-DomainDn $DomainDn)
    }
}

function Get-DomainSid {
    param([string]$DnsHostName, [string]$DomainDn)
    try {
        $entry = [ADSI]('LDAP://' + $DnsHostName + '/' + $DomainDn)
        $raw = $entry.Properties['objectSid']
        $bytes = $null
        if ($raw -is [byte[]]) {
            $bytes = $raw
        } elseif ($null -ne $raw) {
            foreach ($item in $raw) {
                if ($item -is [byte[]]) { $bytes = $item; break }
            }
        }
        if (($null -ne $bytes) -and ($bytes.Length -gt 0)) {
            $sid = [Security.Principal.SecurityIdentifier]::new($bytes, 0)
            return [string]$sid.Value
        }
    } catch {
        return ''
    }
    return ''
}

function Get-SidFromQueryResult {
    param($QueryResults, [string]$Id)
    try {
        if ($null -eq $QueryResults) { return '' }
        if (-not $QueryResults.Contains($Id)) { return '' }
        $rows = @($QueryResults[$Id]['rows'])
        if ($rows.Count -eq 0) { return '' }
        $attributes = $rows[0]['a']
        if ($null -eq $attributes) { return '' }
        $encoded = @()
        foreach ($name in $attributes.Keys) {
            if ([string]$name -eq 'objectSid') { $encoded = @($attributes[$name]); break }
        }
        if ($encoded.Count -eq 0) { return '' }
        $bytes = [Convert]::FromBase64String([string]$encoded[0])
        if ($bytes.Length -eq 0) { return '' }
        $sid = [Security.Principal.SecurityIdentifier]::new($bytes, 0)
        return [string]$sid.Value
    } catch {
        return ''
    }
}

function Get-RegistrySettings {
    $items = @()
    foreach ($setting in $script:RegistrySettings) {
        $item = [ordered]@{
            source = 'registry'
            key = ('HKLM\' + $setting['path'] + '\' + $setting['name'])
            status = 'ok'
            value = ''
        }
        $found = $false
        $value = $null
        try {
            $subKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($setting['path'], $false)
            if ($null -ne $subKey) {
                try {
                    $value = $subKey.GetValue($setting['name'], $null)
                    $found = ($null -ne $value)
                } finally {
                    $subKey.Close()
                }
            }
        } catch {
            $found = $false
            $value = $null
        }
        if (-not $found) {
            $item['status'] = 'unavailable'
            $item['value'] = ''
        } elseif ($setting['name'] -eq 'VulnerableChannelAllowList') {
            $item['value'] = 'present'
        } else {
            $encoded = ConvertTo-DirectoryValue $value
            if ($null -eq $encoded) { $item['value'] = '' } else { $item['value'] = $encoded }
        }
        $items += $item
    }
    return ,[ordered]@{ status = 'ok'; error_code = ''; items = $items }
}

function Measure-PreferenceFile {
    param([string]$Text, [string]$FileName)
    $cpasswordCount = 0
    $autologonCount = 0
    $readerSettings = New-Object System.Xml.XmlReaderSettings
    $readerSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $readerSettings.XmlResolver = $null
    $reader = $null
    try {
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($Text), $readerSettings)
        while ($reader.Read()) {
            if ($reader.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            if (-not $reader.HasAttributes) { continue }
            if (-not [string]::IsNullOrEmpty($reader.GetAttribute('cpassword'))) {
                $cpasswordCount = $cpasswordCount + 1
            }
            if (($FileName -eq 'Registry.xml') -and ($reader.LocalName -eq 'Properties')) {
                if (($reader.GetAttribute('name') -eq 'DefaultPassword') -or ($reader.GetAttribute('name') -eq 'AutoAdminLogon')) {
                    $autologonCount = $autologonCount + 1
                }
            }
        }
    } catch {
        return $null
    } finally {
        if ($null -ne $reader) { $reader.Close() }
    }
    return ,@{ cpassword = $cpasswordCount; autologon = $autologonCount }
}

function Get-RelativeRegistryPath {
    param([string]$Path)
    $candidate = $Path.Trim()
    if ($candidate -like 'HKEY_LOCAL_MACHINE\*') {
        $candidate = 'SYSTEM\' + $candidate.Substring(19)
    } elseif ($candidate -like 'HKLM\*') {
        $candidate = $candidate.Substring(5)
    } else {
        return $null
    }
    foreach ($setting in $script:RegistrySettings) {
        if ($candidate -ieq ($setting['path'] + '\' + $setting['name'])) { return $candidate }
    }
    return $null
}

function Read-GptTemplate {
    param([string]$Gpo, [string]$Text)
    $items = @()
    $section = ''
    foreach ($line in ($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '') { continue }
        if ($trimmed.StartsWith('[') -and $trimmed.EndsWith(']')) {
            $section = $trimmed.Substring(1, $trimmed.Length - 2).Trim()
            continue
        }
        if (($section -eq 'System Access') -or ($section -eq 'Kerberos Policy')) {
            $position = $trimmed.IndexOf('=')
            if ($position -lt 1) { continue }
            $key = $trimmed.Substring(0, $position).Trim()
            $value = $trimmed.Substring($position + 1).Trim()
            if ($key -eq '') { continue }
            $items += [ordered]@{ gpo = $Gpo; section = $section; key = $key; value = $value }
            continue
        }
        if ($section -eq 'Registry Values') {
            $parts = $trimmed -split ','
            if ($parts.Count -lt 3) { continue }
            $relative = Get-RelativeRegistryPath $parts[0]
            if ($null -eq $relative) { continue }
            $value = ($parts[2..($parts.Count - 1)] -join ',').Trim()
            $items += [ordered]@{ gpo = $Gpo; section = $section; key = ('HKLM\' + $relative); value = $value }
        }
    }
    return $items
}

function Get-GppCanonicalName {
    param([string]$FileName)
    $entry = $script:GppFiles[$FileName.ToLowerInvariant()]
    if ($null -eq $entry) { return '' }
    return [string]$entry[1]
}

function Get-GppPath {
    param([string]$Scope, [string]$FileName)
    $entry = $script:GppFiles[$FileName.ToLowerInvariant()]
    if ($null -eq $entry) { return $Scope + '/Preferences/' + $script:OtherFileName }
    return $Scope + '/Preferences/' + [string]$entry[0] + '/' + [string]$entry[1]
}

function Test-ReparsePoint {
    # A symlink or a junction: it is never followed and never read.
    param($Entry)
    return ([int]($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) -ne 0
}

function Get-FolderEntries {
    # The entries of a folder, or $null when the folder could not be listed.
    # As in the Samba collector, every listing counts its own links in
    # skipped_special, whatever their names, and drops them: a link is never
    # followed.  The entries past the cap of the walk are dropped and
    # counted too.
    param([string]$Path, $Counters)
    $listed = $null
    try {
        $listed = @(Get-ChildItem -LiteralPath $Path -Force)
    } catch {
        return $null
    }
    $entries = @()
    foreach ($entry in $listed) {
        if (Test-ReparsePoint $entry) {
            $Counters['skipped_special'] = $Counters['skipped_special'] + 1
            continue
        }
        $entries += $entry
    }
    if ($entries.Count -gt $script:MaxEntriesPerDirectory) {
        $Counters['skipped_special'] = $Counters['skipped_special'] + ($entries.Count - $script:MaxEntriesPerDirectory)
        $entries = @($entries[0..($script:MaxEntriesPerDirectory - 1)])
    }
    return ,$entries
}

function Select-NamedFolders {
    # The folders of a listing with that name, whatever their case.  The
    # listing holds no link: Get-FolderEntries counted and dropped them.
    param($Entries, [string]$Name)
    $found = @()
    foreach ($entry in $Entries) {
        if ($entry.PSIsContainer -and ($entry.Name -ieq $Name)) { $found += $entry }
    }
    return $found
}

function ConvertFrom-SysvolBytes {
    # The text of a file of the SYSVOL, with the rules of the Samba
    # collector: a byte order mark picks UTF-8, UTF-16 LE or UTF-16 BE, and
    # a file without one is UTF-8 with replacement characters.  $null when
    # a file with a byte order mark does not decode.
    param([byte[]]$Bytes)
    try {
        if (($Bytes.Length -ge 3) -and ($Bytes[0] -eq 0xEF) -and ($Bytes[1] -eq 0xBB) -and ($Bytes[2] -eq 0xBF)) {
            return (New-Object System.Text.UTF8Encoding($false, $true)).GetString($Bytes, 3, $Bytes.Length - 3)
        }
        if (($Bytes.Length -ge 2) -and ($Bytes[0] -eq 0xFF) -and ($Bytes[1] -eq 0xFE)) {
            return (New-Object System.Text.UnicodeEncoding($false, $false, $true)).GetString($Bytes, 2, $Bytes.Length - 2)
        }
        if (($Bytes.Length -ge 2) -and ($Bytes[0] -eq 0xFE) -and ($Bytes[1] -eq 0xFF)) {
            return (New-Object System.Text.UnicodeEncoding($true, $false, $true)).GetString($Bytes, 2, $Bytes.Length - 2)
        }
    } catch {
        return $null
    }
    return (New-Object System.Text.UTF8Encoding($false, $false)).GetString($Bytes)
}

function Read-SysvolFile {
    # The text of a listed file of the SYSVOL, read at most to the cap.  A
    # link, or a file that could not be opened, is counted in
    # skipped_special; a file over the cap, or one that does not decode, in
    # parse_refused, as the Samba collector counts them.  Both answer $null.
    param($File, $Counters)
    if (Test-ReparsePoint $File) {
        $Counters['skipped_special'] = $Counters['skipped_special'] + 1
        return $null
    }
    $stream = $null
    try {
        $stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    } catch {
        $Counters['skipped_special'] = $Counters['skipped_special'] + 1
        return $null
    }
    $bytes = $null
    try {
        $limit = $script:MaxFileBytes + 1
        $buffer = New-Object byte[] $limit
        $total = 0
        while ($total -lt $limit) {
            $read = $stream.Read($buffer, $total, $limit - $total)
            if ($read -le 0) { break }
            $total = $total + $read
        }
        if ($total -gt $script:MaxFileBytes) {
            $Counters['parse_refused'] = $Counters['parse_refused'] + 1
            return $null
        }
        $bytes = New-Object byte[] $total
        [Array]::Copy($buffer, $bytes, $total)
    } catch {
        $Counters['parse_refused'] = $Counters['parse_refused'] + 1
        return $null
    } finally {
        $stream.Dispose()
    }
    $text = ConvertFrom-SysvolBytes $bytes
    if ($null -eq $text) {
        $Counters['parse_refused'] = $Counters['parse_refused'] + 1
    }
    return $text
}

function Get-PreferenceFiles {
    # The XML files below a Preferences folder.  The walk is the collector's
    # own, as on Samba: a link is counted and never followed, a folder that
    # could not be listed is counted, and the walk stops at a depth cap and
    # counts what is below it.
    param([string]$Path, $Counters, [int]$Depth = 1)
    $found = @()
    if ($Depth -gt $script:MaxDepth) {
        $Counters['skipped_special'] = $Counters['skipped_special'] + 1
        return ,$found
    }
    $entries = Get-FolderEntries $Path $Counters
    if ($null -eq $entries) {
        $Counters['skipped_special'] = $Counters['skipped_special'] + 1
        return ,$found
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer) {
            # The function answers its list whole (the comma of its return),
            # so it is added as a list and never wrapped in @() again.
            $found += Get-PreferenceFiles $entry.FullName $Counters ($Depth + 1)
            continue
        }
        if ($entry.Name.EndsWith('.xml', [StringComparison]::OrdinalIgnoreCase)) { $found += $entry }
    }
    return ,$found
}

function Get-TemplateFiles {
    # The GptTmpl.inf files of a GPO, in every case variant of its folders.
    # The GPO folder is listed again for the template, as the Samba
    # collector lists it, so its links count in this section too.  A folder
    # on the way that could not be listed is counted in skipped_special:
    # what is below it was never read.
    param([string]$GpoPath, $Counters)
    $gpoEntries = Get-FolderEntries $GpoPath $Counters
    if ($null -eq $gpoEntries) {
        $Counters['skipped_special'] = $Counters['skipped_special'] + 1
        return ,@()
    }
    $current = @(Select-NamedFolders $gpoEntries 'Machine')
    foreach ($name in @('Microsoft', 'Windows NT', 'SecEdit', '')) {
        $next = @()
        foreach ($folder in $current) {
            $entries = Get-FolderEntries $folder.FullName $Counters
            if ($null -eq $entries) {
                $Counters['skipped_special'] = $Counters['skipped_special'] + 1
                continue
            }
            if ($name -ne '') {
                $next += @(Select-NamedFolders $entries $name)
                continue
            }
            foreach ($entry in $entries) {
                if ((-not $entry.PSIsContainer) -and ($entry.Name -ieq 'GptTmpl.inf')) { $next += $entry }
            }
        }
        $current = $next
    }
    return ,$current
}

function Get-SysvolResults {
    param($Context, $DeadlineUtc)
    $domainDns = [string]$Context['domain_dns']
    if ($domainDns -eq '') {
        return ,[ordered]@{
            gpp = [ordered]@{
                status = 'unavailable'
                error_code = 'no_such_object'
                items = @()
                skipped_nonguid = 0
                parse_refused = 0
                skipped_special = 0
            }
            gpttmpl = [ordered]@{
                status = 'unavailable'
                error_code = 'no_such_object'
                items = @()
                parse_refused = 0
                skipped_special = 0
            }
        }
    }
    $policiesPath = '\\' + $domainDns + '\SYSVOL\' + $domainDns + '\Policies'
    return ,(Get-PolicyFileResults $policiesPath $DeadlineUtc)
}

function Get-PolicyFileResults {
    param([string]$PoliciesPath, $DeadlineUtc)
    $gppItems = @()
    $gptItems = @()
    $skipped = 0
    $gppCounters = @{ parse_refused = 0; skipped_special = 0 }
    $gptCounters = @{ parse_refused = 0; skipped_special = 0 }
    $gppStatus = 'ok'
    $gppError = ''
    $gptStatus = 'ok'
    $gptError = ''
    $directories = @()
    try {
        $directories = @(Get-ChildItem -LiteralPath $PoliciesPath -Force)
    } catch {
        $mapped = Get-StatusForError $_
        return ,[ordered]@{
            gpp = [ordered]@{
                status = [string]$mapped['status']
                error_code = [string]$mapped['error_code']
                items = @()
                skipped_nonguid = 0
                parse_refused = 0
                skipped_special = 0
            }
            gpttmpl = [ordered]@{
                status = [string]$mapped['status']
                error_code = [string]$mapped['error_code']
                items = @()
                parse_refused = 0
                skipped_special = 0
            }
        }
    }
    $guidDirectories = @()
    foreach ($directory in $directories) {
        if (Test-ReparsePoint $directory) {
            # A link at the Policies root is never followed; the Samba
            # collector counts it in the gpp section.
            $gppCounters['skipped_special'] = $gppCounters['skipped_special'] + 1
            continue
        }
        if (-not $directory.PSIsContainer) { continue }
        if ($directory.Name -notmatch $script:GuidPattern) {
            $skipped = $skipped + 1
            continue
        }
        $guidDirectories += $directory
    }
    foreach ($directory in $guidDirectories) {
        if ([DateTime]::UtcNow -gt $DeadlineUtc) {
            $gppStatus = 'truncated'
            $gppError = 'time_limit'
            $gptStatus = 'truncated'
            $gptError = 'time_limit'
            break
        }
        $gpoEntries = Get-FolderEntries $directory.FullName $gppCounters
        if ($null -eq $gpoEntries) {
            # The GPO folder could not be listed: neither its preferences
            # nor its template were read.
            $gppCounters['skipped_special'] = $gppCounters['skipped_special'] + 1
            $gptCounters['skipped_special'] = $gptCounters['skipped_special'] + 1
            continue
        }
        foreach ($scope in @('Machine', 'User')) {
            foreach ($scopeFolder in @(Select-NamedFolders $gpoEntries $scope)) {
                $scopeEntries = Get-FolderEntries $scopeFolder.FullName $gppCounters
                if ($null -eq $scopeEntries) {
                    $gppCounters['skipped_special'] = $gppCounters['skipped_special'] + 1
                    continue
                }
                foreach ($preferences in @(Select-NamedFolders $scopeEntries 'Preferences')) {
                    foreach ($file in (Get-PreferenceFiles $preferences.FullName $gppCounters)) {
                        $text = Read-SysvolFile $file $gppCounters
                        if ($null -eq $text) { continue }
                        if ($text.Contains('<!DOCTYPE') -or $text.Contains('<!ENTITY')) {
                            $gppCounters['parse_refused'] = $gppCounters['parse_refused'] + 1
                            $text = $null
                            continue
                        }
                        $counts = Measure-PreferenceFile $text (Get-GppCanonicalName $file.Name)
                        $text = $null
                        if ($null -eq $counts) {
                            $gppCounters['parse_refused'] = $gppCounters['parse_refused'] + 1
                            continue
                        }
                        $relative = Get-GppPath $scope $file.Name
                        if ([int]$counts['cpassword'] -gt 0) {
                            $gppItems += [ordered]@{
                                gpo = $directory.Name
                                path = $relative
                                kind = 'cpassword'
                                count = [int]$counts['cpassword']
                            }
                        }
                        if ([int]$counts['autologon'] -gt 0) {
                            $gppItems += [ordered]@{
                                gpo = $directory.Name
                                path = $relative
                                kind = 'autologon'
                                count = [int]$counts['autologon']
                            }
                        }
                    }
                }
            }
        }
        foreach ($template in (Get-TemplateFiles $directory.FullName $gptCounters)) {
            $infText = Read-SysvolFile $template $gptCounters
            if ($null -eq $infText) { continue }
            foreach ($item in (Read-GptTemplate $directory.Name $infText)) { $gptItems += $item }
            $infText = $null
        }
    }
    return ,[ordered]@{
        gpp = [ordered]@{
            status = $gppStatus
            error_code = $gppError
            items = $gppItems
            skipped_nonguid = $skipped
            parse_refused = [int]$gppCounters['parse_refused']
            skipped_special = [int]$gppCounters['skipped_special']
        }
        gpttmpl = [ordered]@{
            status = $gptStatus
            error_code = $gptError
            items = $gptItems
            parse_refused = [int]$gptCounters['parse_refused']
            skipped_special = [int]$gptCounters['skipped_special']
        }
    }
}

function Get-ObjectDepth {
    param($Value, [int]$Level = 1)
    if ($Value -is [System.Collections.IDictionary]) {
        $deepest = $Level
        foreach ($key in $Value.Keys) {
            $child = Get-ObjectDepth $Value[$key] ($Level + 1)
            if ($child -gt $deepest) { $deepest = $child }
        }
        return $deepest
    }
    if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
        $deepest = $Level
        foreach ($item in $Value) {
            $child = Get-ObjectDepth $item ($Level + 1)
            if ($child -gt $deepest) { $deepest = $child }
        }
        return $deepest
    }
    return $Level
}

function Get-DocumentProbe {
    return ,[ordered]@{
        v = 1
        collector = 'windows'
        collector_version = $script:CollectorVersion
        querysetsha = ''
        is_dc = $false
        domain = [ordered]@{
            dns = ''
            domain_dn = ''
            config_dn = ''
            schema_dn = ''
            domain_sid = ''
        }
        identity = [ordered]@{ user = ''; sid = ''; token_group_sids = @('S-1-5-11') }
        started = ''
        elapsed_ms = 0
        queries = [ordered]@{
            probe = [ordered]@{
                status = 'ok'
                error_code = ''
                rows = @([ordered]@{ dn = ''; a = [ordered]@{ probe = @('probe') } })
            }
        }
        files = [ordered]@{
            gpp = [ordered]@{
                status = 'ok'
                error_code = ''
                items = @([ordered]@{ gpo = ''; path = ''; kind = ''; count = 1 })
                skipped_nonguid = 0
                parse_refused = 0
                skipped_special = 0
            }
            gpttmpl = [ordered]@{
                status = 'ok'
                error_code = ''
                items = @([ordered]@{ gpo = ''; section = ''; key = ''; value = '' })
                parse_refused = 0
                skipped_special = 0
            }
        }
        settings = [ordered]@{
            status = 'ok'
            error_code = ''
            items = @([ordered]@{ source = 'registry'; key = ''; status = 'ok'; value = '' })
        }
    }
}

if ($MyInvocation.InvocationName -eq '.') {
    Write-Fail 2 'newton-ad collector: the collector is not dot-sourced'
}

if ($args.Count -ne 0) {
    Write-Fail 2 'newton-ad collector: the collector takes no arguments'
}

$Dir = Split-Path -Parent $PSCommandPath
$scriptPath = Join-Path $Dir 'collector.ps1'
$queriesPath = Join-Path $Dir 'queries.json'
$forbiddenPath = Join-Path $Dir 'forbidden.json'

foreach ($required in @($scriptPath, $queriesPath, $forbiddenPath)) {
    if (-not (Test-Path -LiteralPath $required)) {
        Write-Fail 1 'newton-ad collector: the collector files are missing'
    }
}

$queriesBytes = $null
$forbiddenBytes = $null
try {
    $queriesBytes = [IO.File]::ReadAllBytes($queriesPath)
    $forbiddenBytes = [IO.File]::ReadAllBytes($forbiddenPath)
} catch {
    Write-Fail 1 'newton-ad collector: the collector files are missing'
}

$hashAlgorithm = [Security.Cryptography.SHA256]::Create()
try {
    $hashBytes = $hashAlgorithm.ComputeHash($queriesBytes)
} finally {
    $hashAlgorithm.Dispose()
}
$querysetsha = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })

$queriesDocument = $null
$forbiddenDocument = $null
try {
    $queriesDocument = ([Text.Encoding]::UTF8.GetString($queriesBytes) | ConvertFrom-Json)
    $forbiddenDocument = ([Text.Encoding]::UTF8.GetString($forbiddenBytes) | ConvertFrom-Json)
} catch {
    Write-Fail 1 'newton-ad collector: the collector files are unreadable'
}

$forbidden = @{}
foreach ($name in @($forbiddenDocument)) {
    if ($null -eq $name) { continue }
    $forbidden[([string]$name).ToLowerInvariant()] = $true
}

foreach ($checked in @($Dir, $scriptPath, $queriesPath, $forbiddenPath)) {
    $safe = $false
    try {
        $safe = Test-SafeInstallAcl $checked
    } catch {
        $safe = $false
    }
    if (-not $safe) {
        Write-Fail 2 'newton-ad collector: the install is not safe'
    }
}

$queryList = @(Get-JsonProperty $queriesDocument 'queries' @())
foreach ($query in $queryList) {
    $problem = Get-ForbiddenProblem $query $forbidden
    if ($problem -eq 'attribute') {
        Write-Fail 2 'newton-ad collector: the query set requests a forbidden attribute'
    }
    if ($problem -eq 'filter') {
        Write-Fail 2 'newton-ad collector: the query set filter names a forbidden attribute'
    }
}

$rootDse = $null
try {
    $rootDse = [ADSI]'LDAP://RootDSE'
} catch {
    Write-Fail 1 'newton-ad collector: the directory did not answer'
}
$domainDn = Get-DirectoryProperty $rootDse 'defaultNamingContext'
$configDn = Get-DirectoryProperty $rootDse 'configurationNamingContext'
$schemaDn = Get-DirectoryProperty $rootDse 'schemaNamingContext'
$dnsHostName = Get-DirectoryProperty $rootDse 'dnsHostName'
if (($domainDn -eq '') -or ($configDn -eq '') -or ($schemaDn -eq '') -or ($dnsHostName -eq '')) {
    Write-Fail 1 'newton-ad collector: the directory did not answer'
}

$isDc = $false
$hostLabels = $dnsHostName -split '\.'
$localName = [string]$env:COMPUTERNAME
if (($hostLabels.Count -gt 0) -and ($localName -ne '')) {
    $isDc = ([string]$hostLabels[0] -ieq $localName)
}

$domainDns = Get-DomainDnsName $domainDn
$domainSid = Get-DomainSid $dnsHostName $domainDn

$context = @{
    domain_dn = $domainDn
    config_dn = $configDn
    schema_dn = $schemaDn
    dns_host = $dnsHostName
    domain_dns = $domainDns
}

$startedUtc = [DateTime]::UtcNow
$deadlineUtc = $startedUtc.AddSeconds($script:DeadlineSeconds)
$script:DeadlineUtc = $deadlineUtc
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$queryResults = [ordered]@{}
foreach ($query in $queryList) {
    $id = [string](Get-JsonProperty $query 'id' '')
    if ([DateTime]::UtcNow -gt $deadlineUtc) {
        $queryResults[$id] = [ordered]@{ status = 'truncated'; error_code = 'time_limit'; rows = @() }
        continue
    }
    $queryResults[$id] = Invoke-CollectorQuery $query $context
}

if ($domainSid -eq '') {
    $domainSid = Get-SidFromQueryResult $queryResults 'domain_head'
}
if ($domainSid -eq '') {
    Write-Fail 1 'newton-ad collector: the domain sid is unknown'
}

$files = Get-SysvolResults $context $deadlineUtc

if ($isDc) {
    $settings = Get-RegistrySettings
} else {
    $settings = [ordered]@{ status = 'not_collected'; error_code = 'not_a_dc'; items = @() }
}

$identity = Get-CollectorIdentity

$stopwatch.Stop()
$elapsedMs = [int64]$stopwatch.ElapsedMilliseconds

$document = [ordered]@{
    v = 1
    collector = 'windows'
    collector_version = $script:CollectorVersion
    querysetsha = $querysetsha
    is_dc = $isDc
    domain = [ordered]@{
        dns = $domainDns
        domain_dn = $domainDn
        config_dn = $configDn
        schema_dn = $schemaDn
        domain_sid = $domainSid
    }
    identity = $identity
    started = $startedUtc.ToString('yyyyMMddTHHmmss', [Globalization.CultureInfo]::InvariantCulture) + 'Z'
    elapsed_ms = $elapsedMs
    queries = $queryResults
    files = $files
    settings = $settings
}

$probeDepth = Get-ObjectDepth (Get-DocumentProbe)
if ($probeDepth -gt 12) {
    Write-Fail 1 'newton-ad collector: the json depth is not enough'
}

$json = $document | ConvertTo-Json -Depth 12 -Compress
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::Out.Write($json + "`n")
exit 0
