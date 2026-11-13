param(
    [string]$HelperPath = 'C:\ProgramData\Newton\ad\write.ps1'
)

# The live probe of the Windows write helper.
#
# Run this on a real domain controller, under Windows
# PowerShell 5.1, as the write account:
#
#     powershell.exe -NoProfile -ExecutionPolicy Bypass -File win_write_live_probe.ps1
#
# It writes NOTHING.  It dot-sources the helper, builds the real LDAP
# adapter and prints one JSON line per check:
#
#   bind        the connection to this DC and the bind;
#   rootdse     the rootDSE read: the domain DN and the NTDS Settings DN;
#   pdc         the PDC check: the two NTDS Settings DNs compared;
#   resolve     a read-mode resolve of the Administrator;
#   resolve_lower a read-mode resolve of the Administrator by its lowercase
#               name: the directory matches a name without its case and the
#               ids of the answer carry the name in lowercase;
#   tokengroups the token groups of the current account, decoded;
#   privileged  the privileged flag of that account;
#   dc_ou       the DN of the Domain Controllers OU;
#   hex         a hex decode of a fixed test string.
#
# Every line is one JSON object with a "check" field, an "ok" field and the
# facts of the check.  A line with "ok": false says what failed.

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

. $HelperPath

function Write-ProbeLine {
    param([string]$Check, [bool]$Ok, $Facts)
    $line = [ordered]@{ check = $Check; ok = $Ok }
    if ($null -ne $Facts) {
        if ($Facts -is [System.Collections.IDictionary]) {
            foreach ($key in $Facts.Keys) { $line[[string]$key] = $Facts[$key] }
        } else {
            $line['value'] = $Facts
        }
    }
    [Console]::Out.Write(($line | ConvertTo-Json -Depth 8 -Compress) + "`n")
}

$adapter = $null
$bindOk = $false
$bindFact = ''
try {
    $adapter = Get-NewtonLdapAdapter
    $bindOk = ($null -ne $adapter)
    $bindFact = [string]$adapter.Host
} catch {
    $bindFact = $_.Exception.Message
}
Write-ProbeLine 'bind' $bindOk ([ordered]@{ host = $bindFact })

if (-not $bindOk) { exit 0 }

# the rootDSE
try {
    $root = Get-NewtonRootDse $adapter
    $domainDn = Get-NewtonDomainDn $adapter
    $serviceName = Get-NewtonAttrString $root 'dsServiceName' 0
    Write-ProbeLine 'rootdse' ($null -ne $root) ([ordered]@{
        domain_dn = $domainDn
        ds_service_name = $serviceName
    })
} catch {
    Write-ProbeLine 'rootdse' $false ([ordered]@{ error = $_.Exception.Message })
}

# the PDC check
try {
    $domainDn = Get-NewtonDomainDn $adapter
    $isPdc = Test-NewtonIsPdc $adapter $domainDn
    $head = Get-NewtonDomainHead $adapter $domainDn
    Write-ProbeLine 'pdc' ([bool]$isPdc) ([ordered]@{
        fsmoroleowner = (Get-NewtonAttrString $head 'fSMORoleOwner' 0)
        dcservicename = (Get-NewtonAttrString (Get-NewtonRootDse $adapter) 'dsServiceName' 0)
    })
} catch {
    Write-ProbeLine 'pdc' $false ([ordered]@{ error = $_.Exception.Message })
}

# a read-mode resolve of the Administrator
try {
    $request = @{
        v = 1
        mode = 'read'
        device = (Get-NewtonDeviceName)
        verb = 'uac-clear'
        target = @{ sam = 'Administrator' }
    }
    $response = Invoke-NewtonRead -Request $request -Adapter $adapter
    Write-ProbeLine 'resolve' ($response['code'] -eq 'ok') ([ordered]@{
        code = [string]$response['code']
        live = $response['live']
        ids = $response['ids']
        facts = $response['facts']
    })
} catch {
    Write-ProbeLine 'resolve' $false ([ordered]@{ error = $_.Exception.Message })
}

# a read-mode resolve of the Administrator by its lowercase name
try {
    $request = @{
        v = 1
        mode = 'read'
        device = (Get-NewtonDeviceName)
        verb = 'uac-clear'
        target = @{ sam = 'administrator' }
    }
    $response = Invoke-NewtonRead -Request $request -Adapter $adapter
    $ids = $response['ids']
    $sam = ''
    if ($null -ne $ids) { $sam = [string]$ids['sam'] }
    $lower = ($sam -ceq $sam.ToLowerInvariant())
    Write-ProbeLine 'resolve_lower' (([string]$response['code'] -eq 'ok') -and $lower) ([ordered]@{
        code = [string]$response['code']
        sam = $sam
        lower = $lower
        ids = $ids
    })
} catch {
    Write-ProbeLine 'resolve_lower' $false ([ordered]@{ error = $_.Exception.Message })
}

# the token groups of the current account, decoded
$tokenGroups = @()
try {
    $domainDn = Get-NewtonDomainDn $adapter
    $sam = Get-NewtonWriteAccountSam
    $account = Find-NewtonObjectBySam $adapter $sam $domainDn
    if ($null -eq $account) {
        throw 'the write account is not there'
    }
    $entries = Search-Newton $adapter ([string]$account['dn']) '(objectClass=*)' 'base' ([string[]]@('tokenGroups'))
    if ($entries.Count -ne 1) { throw 'the token groups did not answer' }
    foreach ($bytes in (Get-NewtonAttrByteArrays $entries[0] 'tokenGroups')) {
        $tokenGroups += (ConvertFrom-NewtonSidBytes $bytes)
    }
    Write-ProbeLine 'tokengroups' ($tokenGroups.Count -gt 0) ([ordered]@{
        sam = $sam
        count = $tokenGroups.Count
        sids = $tokenGroups
    })
} catch {
    Write-ProbeLine 'tokengroups' $false ([ordered]@{ error = $_.Exception.Message })
}

# the privileged flag of the write account
try {
    $domainDn = Get-NewtonDomainDn $adapter
    $privileged = Test-NewtonWriteAccountPrivileged $adapter $domainDn
    Write-ProbeLine 'privileged' (-not [bool]$privileged) ([ordered]@{
        privileged = [bool]$privileged
    })
} catch {
    Write-ProbeLine 'privileged' $false ([ordered]@{ error = $_.Exception.Message })
}

# the DN of the Domain Controllers OU
try {
    $domainDn = Get-NewtonDomainDn $adapter
    $dcOu = 'OU=Domain Controllers,' + $domainDn
    $entries = Search-Newton $adapter $dcOu '(objectClass=*)' 'base' ([string[]]@('objectClass'))
    $classes = @()
    if ($entries.Count -eq 1) {
        foreach ($value in (Get-NewtonAttrStrings $entries[0] 'objectClass')) { $classes += $value }
    }
    Write-ProbeLine 'dc_ou' ($entries.Count -eq 1) ([ordered]@{
        dn = $dcOu
        object_class = $classes
    })
} catch {
    Write-ProbeLine 'dc_ou' $false ([ordered]@{ error = $_.Exception.Message })
}

# a hex decode of a fixed test string
try {
    $bytes = ConvertFrom-NewtonHex '00112233445566778899aabbccddeeff'
    $text = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    Write-ProbeLine 'hex' ($text -eq '00112233445566778899aabbccddeeff') ([ordered]@{
        length = $bytes.Length
        hex = $text
    })
} catch {
    Write-ProbeLine 'hex' $false ([ordered]@{ error = $_.Exception.Message })
}

exit 0
