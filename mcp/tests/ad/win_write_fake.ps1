# The fake LDAP adapter and the fake scheduler of the Windows write helper.
#
# The tests dot-source this file beside write.ps1 and put the fakes in the
# test seams of the helper ($script:LdapAdapter, $script:SchedulerAdapter).
#
# The fake behaves the way the directory of the lab DC behaves, as it was
# measured on 2026-11-09 (SPEC section 9):
#
#   - searches return only requested, lower-case attribute names;
#   - binary attributes are byte arrays, and tokenGroups is returned only
#     by a base-scope read of the account's own DN;
#   - a modify with a stale old value answers 16 (no such attribute);
#   - a write outside the delegation answers 50 (insufficient access);
#   - an add with a unicodePwd works;
#   - a move is ModifyDN, never a distinguishedName modify.

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

# DirectoryResponse has no public constructor.  The fake exception carries
# the same Response.ResultCode property path as DirectoryOperationException,
# so one helper mapping path handles the fake and the real DC.
if ($null -eq ('NewtonFakeDirectoryOperationException' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
public sealed class NewtonFakeDirectoryResponse {
    public int ResultCode { get; private set; }
    public NewtonFakeDirectoryResponse(int code) { ResultCode = code; }
}
public sealed class NewtonFakeDirectoryOperationException : Exception {
    public NewtonFakeDirectoryResponse Response { get; private set; }
    public NewtonFakeDirectoryOperationException(int code, string message) : base(message) {
        Response = new NewtonFakeDirectoryResponse(code);
    }
}
'@
}

function ConvertTo-NewtonFakeSidBytes {
    # The bytes of one SID, the way the directory stores them.
    param([string]$Sid)
    $parts = $Sid.Split('-')
    if ($parts.Count -lt 3) { return $null }
    $revision = 0
    $authority = 0
    if (-not [int]::TryParse($parts[1], [ref]$revision)) { return $null }
    if (-not [int64]::TryParse($parts[2], [ref]$authority)) { return $null }
    $subs = @()
    for ($index = 3; $index -lt $parts.Count; $index++) {
        $number = 0
        if (-not [int64]::TryParse($parts[$index], [ref]$number)) { return $null }
        $subs += $number
    }
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.Add([byte]$revision)
    $bytes.Add([byte]$subs.Count)
    $authorityBytes = [System.BitConverter]::GetBytes([int64]$authority)
    for ($index = 5; $index -ge 0; $index--) { $bytes.Add($authorityBytes[$index]) }
    foreach ($number in $subs) {
        $value = [System.BitConverter]::GetBytes([int64]$number)
        for ($index = 0; $index -lt 4; $index++) { $bytes.Add($value[$index]) }
    }
    return ,$bytes.ToArray()
}

function ConvertFrom-NewtonFakeSid {
    # The SID of some bytes.
    param([byte[]]$Bytes)
    if (($null -eq $Bytes) -or ($Bytes.Length -lt 8)) { return '' }
    $authority = 0
    for ($index = 2; $index -le 7; $index++) { $authority = ($authority -shl 8) -bor [int64]$Bytes[$index] }
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

function ConvertFrom-NewtonFakeEscaped {
    # The bytes of an escaped LDAP filter value.
    param([string]$Text)
    $bytes = New-Object System.Collections.Generic.List[byte]
    $index = 0
    while ($index -lt $Text.Length) {
        if ($Text[$index] -eq '\') {
            $index = $index + 1
            if (($index + 1) -gt $Text.Length) { return $null }
            $hex = $Text.Substring($index, 2)
            $bytes.Add([Convert]::ToByte($hex, 16))
            $index = $index + 2
            continue
        }
        $bytes.Add([byte][char]$Text[$index])
        $index = $index + 1
    }
    return ,$bytes.ToArray()
}

function ConvertFrom-NewtonFakeFilterText {
    # The text of an escaped filter value, as the directory reads it.
    param([string]$Text)
    $bytes = ConvertFrom-NewtonFakeEscaped $Text
    if ($null -eq $bytes) { return '' }
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function New-NewtonFakeLdapError {
    # The exception of a failed LDAP call.  The helper reads the result code
    # of a DirectoryOperationException; the fake carries the same code.
    param([int]$Code, [string]$Message)
    return (New-Object NewtonFakeDirectoryOperationException -ArgumentList $Code, $Message)
}

function ConvertTo-NewtonFakeEntry {
    # The entry of one object of the fake directory.
    param($Object, [string[]]$Requested, [string]$Base, [string]$Scope)
    $attributes = @{}
    foreach ($requestedName in @($Requested)) {
        $key = ([string]$requestedName).ToLowerInvariant()
        if ($key -eq 'distinguishedname') {
            $attributes[$key] = @([string]$Object['dn'])
            continue
        }
        if (($key -eq 'objectguid') -and ($null -ne $Object['guid'])) {
            $attributes[$key] = ([guid][string]$Object['guid']).ToByteArray()
            continue
        }
        if (($key -eq 'objectsid') -and ($null -ne $Object['sid'])) {
            $attributes[$key] = (ConvertTo-NewtonFakeSidBytes ([string]$Object['sid']))
            continue
        }
        if ($key -eq 'tokengroups') {
            if (($Scope -eq 'base') -and ($Base -ieq [string]$Object['dn'])) {
                $groups = @()
                foreach ($sid in @($Object['token_groups'])) {
                    $groups += ,(ConvertTo-NewtonFakeSidBytes ([string]$sid))
                }
                if ($groups.Count -gt 0) { $attributes[$key] = $groups }
            }
            continue
        }
        if (($null -ne $Object['values']) -and $Object['values'].ContainsKey($key)) {
            $attributes[$key] = $Object['values'][$key]
        }
    }
    return @{ dn = [string]$Object['dn']; attrs = $attributes }
}

function Get-NewtonFakeFilter {
    # The filter of a search, as the fake understands it.
    param([string]$Filter)
    if ($Filter -match '\A\(objectGuid=(.*)\)\z') {
        $bytes = ConvertFrom-NewtonFakeEscaped $Matches[1]
        if ($null -eq $bytes) { return @{ kind = 'none' } }
        return @{ kind = 'guid'; value = [string]([guid]::new($bytes)).ToString() }
    }
    if ($Filter -match '\A\(objectSid=(.*)\)\z') {
        $bytes = ConvertFrom-NewtonFakeEscaped $Matches[1]
        if ($null -eq $bytes) { return @{ kind = 'none' } }
        return @{ kind = 'sid'; value = (ConvertFrom-NewtonFakeSid $bytes) }
    }
    if ($Filter -match '\A\(sAMAccountName=(.*)\)\z') {
        return @{ kind = 'sam'; value = $Matches[1] }
    }
    if ($Filter -match '\A\(userPrincipalName=(.*)\)\z') {
        return @{ kind = 'upn'; value = (ConvertFrom-NewtonFakeFilterText $Matches[1]) }
    }
    if ($Filter -match '\A\(member=(.*)\)\z') {
        return @{ kind = 'member'; value = (ConvertFrom-NewtonFakeFilterText $Matches[1]) }
    }
    if ($Filter -match '\A\(objectClass=(.*)\)\z') {
        return @{ kind = 'class'; value = $Matches[1] }
    }
    return @{ kind = 'none' }
}

function New-NewtonFakeLdap {
    # The fake directory of one case.
    param([hashtable]$Config, $CallLog = $null)
    $domainDn = [string]$Config['domain_dn']
    $serviceName = [string]$Config['service_name']
    $dnsDomain = [string]$Config['dns_domain']
    $pdc = $true
    if ($null -ne $Config['pdc']) { $pdc = [bool]$Config['pdc'] }

    $fake = [pscustomobject]@{
        DomainDn = $domainDn
        ServiceName = $serviceName
        DnsDomain = $dnsDomain
        Log = (New-Object System.Collections.ArrayList)
        CallLog = $CallLog
        Objects = @{}
        Usn = 100
        WriteOccurred = $false
        SearchErrorsAfterWrite = 0
        CreatedMember = ''
        LeakIndexes = $false
        CreatedMissingGuid = $false
        CreatedMissingUsn = $false
        DeleteError = 0
    }
    if ($null -ne $Config['leak_indexes']) {
        # The real adapter of the helper leaked the index of every entry it
        # added: DirectoryAttributeModificationCollection.Add and
        # DirectoryAttributeCollection.Add return it.  The switch
        # puts the defect back, so the guard of the entry point can be tested.
        $fake.LeakIndexes = [bool]$Config['leak_indexes']
    }
    if ($null -ne $Config['created_member']) {
        $fake.CreatedMember = [string]$Config['created_member']
    }
    if ($null -ne $Config['search_errors_after_write']) {
        $fake.SearchErrorsAfterWrite = [int]$Config['search_errors_after_write']
    }
    if ($null -ne $Config['created_missing_guid']) {
        $fake.CreatedMissingGuid = [bool]$Config['created_missing_guid']
    }
    if ($null -ne $Config['created_missing_usn']) {
        $fake.CreatedMissingUsn = [bool]$Config['created_missing_usn']
    }
    if ($null -ne $Config['ldap_delete_error']) {
        $fake.DeleteError = [int]$Config['ldap_delete_error']
    }

    $fake | Add-Member -MemberType ScriptMethod -Name AddObject -Value {
        param($Object)
        $this.Objects[[string]$Object['dn']] = $Object
    }

    $fake | Add-Member -MemberType ScriptMethod -Name ObjectByDn -Value {
        param($Dn)
        if ($this.Objects.ContainsKey([string]$Dn)) { return $this.Objects[[string]$Dn] }
        return $null
    }

    $fake | Add-Member -MemberType ScriptMethod -Name Search -Value {
        param($Base, $Filter, $Scope, $Attributes)
        [void]$this.Log.Add(('search ' + [string]$Base + ' ' + [string]$Filter + ' ' + [string]$Scope))
        if ($null -ne $this.CallLog) {
            [void]$this.CallLog.Add('ldap:search ' + [string]$Filter)
        }
        if ($this.WriteOccurred -and ($this.SearchErrorsAfterWrite -gt 0)) {
            $this.SearchErrorsAfterWrite = $this.SearchErrorsAfterWrite - 1
            throw (New-NewtonFakeLdapError 1 'the readback failed')
        }
        $base = [string]$Base
        $scope = [string]$Scope
        $requested = @()
        foreach ($attribute in @($Attributes)) { $requested += [string]$attribute }
        if (($base -eq '') -and ($scope -eq 'base')) {
            # the RootDSE
            $available = @{
                'defaultnamingcontext' = @($this.DomainDn)
                'dsservicename' = @($this.ServiceName)
            }
            $attrs = @{}
            foreach ($name in $requested) {
                $key = $name.ToLowerInvariant()
                if ($available.ContainsKey($key)) { $attrs[$key] = $available[$key] }
            }
            $root = @{ dn = ''; attrs = $attrs }
            return ,@($root)
        }
        if ($base -eq '') {
            throw (New-NewtonFakeLdapError 32 'the object does not exist')
        }
        $filter = Get-NewtonFakeFilter $Filter
        $entries = @()
        foreach ($key in @($this.Objects.Keys)) {
            $object = $this.Objects[$key]
            if ($base -ne '') {
                if ($scope -eq 'base') {
                    if ($key -ine $base) { continue }
                } elseif ($scope -eq 'one') {
                    $separator = $key.IndexOf(',')
                    if ($separator -lt 0) { continue }
                    if ($key.Substring($separator + 1) -ine $base) { continue }
                } else {
                    if (($key -ine $base) -and
                        (-not $key.EndsWith(',' + $base, [StringComparison]::OrdinalIgnoreCase))) { continue }
                }
            }
            $keep = $true
            if ($filter['kind'] -eq 'guid') {
                $keep = ([string]$object['guid'] -ieq [string]$filter['value'])
            } elseif ($filter['kind'] -eq 'sid') {
                $keep = ([string]$object['sid'] -ieq [string]$filter['value'])
            } elseif ($filter['kind'] -eq 'sam') {
                $keep = ([string]$object['sam'] -ieq [string]$filter['value'])
            } elseif ($filter['kind'] -eq 'upn') {
                $keep = ([string]$object['upn'] -ieq [string]$filter['value'])
            } elseif ($filter['kind'] -eq 'member') {
                $keep = $false
                foreach ($member in @($object['member'])) {
                    if ([string]$member -ieq [string]$filter['value']) { $keep = $true; break }
                }
            } elseif ($filter['kind'] -eq 'class') {
                if ([string]$filter['value'] -eq '*') {
                    $keep = $true
                } else {
                    $keep = $false
                    foreach ($class in @($object['object_class'])) {
                        if ([string]$class -ieq [string]$filter['value']) { $keep = $true; break }
                    }
                }
            }
            if (-not $keep) { continue }
            $entries += ,(ConvertTo-NewtonFakeEntry $object $requested $base $scope)
        }
        return ,$entries
    }

    $fake | Add-Member -MemberType ScriptMethod -Name Modify -Value {
        param($Dn, $Attribute, $OldValues, $NewValues)
        [void]$this.Log.Add(('modify ' + [string]$Dn + ' ' + [string]$Attribute))
        if ($null -ne $this.CallLog) {
            [void]$this.CallLog.Add('ldap:modify ' + [string]$Attribute)
        }
        $object = $this.ObjectByDn($Dn)
        if ($null -eq $object) {
            throw (New-NewtonFakeLdapError 32 ('no such object ' + [string]$Dn))
        }
        if ($null -ne $object['modify_error']) {
            throw (New-NewtonFakeLdapError ([int]$object['modify_error']) 'the modify failed')
        }
        if (-not [bool]$object['delegated']) {
            throw (New-NewtonFakeLdapError 50 'the user has insufficient access rights')
        }
        if ([string]$Attribute -ieq 'distinguishedName') {
            throw (New-NewtonFakeLdapError 53 'the server is unwilling to perform a DN modify')
        }
        $key = ([string]$Attribute).ToLowerInvariant()
        $current = @()
        if ($null -ne $object['values'] -and $object['values'].ContainsKey($key)) {
            $current = @($object['values'][$key])
        }
        foreach ($old in @($OldValues)) {
            $found = $false
            foreach ($value in $current) {
                if ([string]$value -ceq [string]$old) { $found = $true; break }
            }
            if (-not $found) {
                throw (New-NewtonFakeLdapError 16 'the requested attribute does not exist')
            }
        }
        $updated = @()
        foreach ($value in $current) {
            $drop = $false
            foreach ($old in @($OldValues)) {
                if ([string]$value -ceq [string]$old) { $drop = $true; break }
            }
            if (-not $drop) { $updated += [string]$value }
        }
        foreach ($new in @($NewValues)) { $updated += [string]$new }
        if ($updated.Count -eq 0) {
            $object['values'].Remove($key)
        } else {
            $object['values'][$key] = $updated
        }
        $this.Usn = $this.Usn + 1
        $object['usn_changed'] = $this.Usn
        if ($null -ne $object['drift_after_write']) {
            $object['values'][$key] = @([string]$object['drift_after_write'])
        }
        $this.WriteOccurred = $true
        if ($null -ne $object['modify_error_after_write']) {
            # the server applied the modify and the answer was lost (a
            # timeout, a dropped connection): the caller sees an error for
            # a write that landed.  It happens once.
            $lost = [int]$object['modify_error_after_write']
            $object['modify_error_after_write'] = $null
            throw (New-NewtonFakeLdapError $lost 'the answer of the modify was lost')
        }
        if ($this.LeakIndexes) {
            # the defect of the real adapter: the index of every
            # modification reaches the pipeline of the caller
            $index = 0
            foreach ($old in @($OldValues)) {
                Write-Output $index
                $index = $index + 1
            }
            foreach ($new in @($NewValues)) {
                Write-Output $index
                $index = $index + 1
            }
        }
    }

    $fake | Add-Member -MemberType ScriptMethod -Name ModifyDN -Value {
        param($Dn, $NewParentDn, $NewRdn)
        [void]$this.Log.Add(('modifydn ' + [string]$Dn + ' ' + [string]$NewParentDn + ' ' + [string]$NewRdn))
        if ($null -ne $this.CallLog) { [void]$this.CallLog.Add('ldap:modifydn ' + [string]$Dn) }
        $object = $this.ObjectByDn($Dn)
        if ($null -eq $object) {
            throw (New-NewtonFakeLdapError 32 ('no such object ' + [string]$Dn))
        }
        if (-not [bool]$object['delegated']) {
            throw (New-NewtonFakeLdapError 50 'the user has insufficient access rights')
        }
        $newDn = [string]$NewRdn + ',' + [string]$NewParentDn
        if ($this.Objects.ContainsKey($newDn)) {
            throw (New-NewtonFakeLdapError 68 'the entry already exists')
        }
        $this.Objects.Remove([string]$Dn)
        $object['dn'] = $newDn
        $object['parent'] = [string]$NewParentDn
        $this.Objects[$newDn] = $object
        $this.WriteOccurred = $true
        if ($null -ne $object['move_drift_to']) {
            # somebody moved the object again right after the write
            $driftDn = [string]$object['move_drift_to']
            $this.Objects.Remove($newDn)
            $object['dn'] = $driftDn
            $this.Objects[$driftDn] = $object
        }
    }

    $fake | Add-Member -MemberType ScriptMethod -Name Add -Value {
        param($Dn, $Attributes)
        [void]$this.Log.Add(('add ' + [string]$Dn))
        if ($null -ne $this.CallLog) {
            [void]$this.CallLog.Add('ldap:add ' + [string]$Dn)
        }
        if ($this.Objects.ContainsKey([string]$Dn)) {
            throw (New-NewtonFakeLdapError 68 'the entry already exists')
        }
        $parts = ([string]$Dn).Split(',')
        $cn = ''
        if ($parts.Count -gt 0) {
            $label = $parts[0].Trim()
            if ($label.StartsWith('CN=')) { $cn = $label.Substring(3) }
        }
        $parentDn = ''
        if (($parts.Count -gt 1) -and ($cn -ne '')) { $parentDn = ([string]$Dn).Substring($cn.Length + 4) }
        $parent = $this.ObjectByDn($parentDn)
        if (($null -eq $parent) -or (-not [bool]$parent['delegated'])) {
            throw (New-NewtonFakeLdapError 50 'the user has insufficient access rights')
        }
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digest = $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$cn))
        } finally {
            $algorithm.Dispose()
        }
        $guidBytes = New-Object byte[] 16
        [System.Array]::Copy($digest, $guidBytes, 16)
        $object = @{
            dn = [string]$Dn
            guid = ([guid]$guidBytes).ToString()
            sid = 'S-1-5-21-1-2-3-9999'
            sam = $cn
            object_class = @('top', 'person', 'organizationalPerson', 'user')
            uac = 514
            etypes = 0
            lockout = 0
            maq = $null
            admin_count = 0
            member_of = @()
            member = @()
            primary_group_id = 513
            token_groups = @('S-1-5-21-1-2-3-513')
            parent = $parentDn
            usn_changed = $this.Usn
            delegated = $true
            upn = $null
            values = @{}
        }
        if ($this.CreatedMember -ne '') {
            $object['member'] = @($this.CreatedMember)
            $object['values']['member'] = @($this.CreatedMember)
        }
        foreach ($name in $Attributes.Keys) {
            $key = ([string]$name).ToLowerInvariant()
            $value = $Attributes[$name]
            if ($value -is [byte[]]) {
                $object['values'][$key] = $value
                continue
            }
            $texts = @()
            foreach ($item in @($value)) { $texts += [string]$item }
            $object['values'][$key] = $texts
        }
        if ($object['values'].ContainsKey('samaccountname')) {
            $object['sam'] = [string]$object['values']['samaccountname'][0]
        }
        if ($object['values'].ContainsKey('userprincipalname')) {
            $object['upn'] = [string]$object['values']['userprincipalname'][0]
        }
        if ($object['values'].ContainsKey('useraccountcontrol')) {
            $object['uac'] = [int64]$object['values']['useraccountcontrol'][0]
        }
        if ($object['values'].ContainsKey('objectclass')) {
            $object['object_class'] = @($object['values']['objectclass'])
        }
        $object['values']['usnchanged'] = @([string]$this.Usn)
        $this.Usn = $this.Usn + 1
        $object['usn_changed'] = $this.Usn
        if ($this.CreatedMissingGuid) { $object['guid'] = $null }
        if ($this.CreatedMissingUsn) {
            $object['values'].Remove('usnchanged')
            $object['usn_changed'] = $null
        }
        $this.Objects[[string]$Dn] = $object
        $this.WriteOccurred = $true
        if ($this.LeakIndexes) {
            # the defect of the real adapter: the index of every
            # attribute reaches the pipeline of the caller
            $index = 0
            foreach ($name in $Attributes.Keys) {
                Write-Output $index
                $index = $index + 1
            }
        }
    }

    $fake | Add-Member -MemberType ScriptMethod -Name Delete -Value {
        param($Dn)
        [void]$this.Log.Add(('delete ' + [string]$Dn))
        if ($null -ne $this.CallLog) {
            [void]$this.CallLog.Add('ldap:delete ' + [string]$Dn)
        }
        $object = $this.ObjectByDn($Dn)
        if ($null -eq $object) {
            throw (New-NewtonFakeLdapError 32 ('no such object ' + [string]$Dn))
        }
        if (-not [bool]$object['delegated']) {
            throw (New-NewtonFakeLdapError 50 'the user has insufficient access rights')
        }
        if ($this.DeleteError -ne 0) {
            throw (New-NewtonFakeLdapError $this.DeleteError 'the delete failed')
        }
        $this.Objects.Remove([string]$Dn)
        $this.WriteOccurred = $true
    }

    # NTDS Settings objects live below Sites/Configuration and do not carry
    # dNSHostName.  RootDSE dsServiceName is the local NTDS Settings DN.
    $configurationDn = 'CN=Configuration,' + $domainDn
    $serversDn = 'CN=Servers,CN=Default-First-Site-Name,CN=Sites,' + $configurationDn
    $localNtdsDn = 'CN=NTDS Settings,CN=' + $serviceName.Split('.')[0] + ',' + $serversDn
    $ownerDn = $localNtdsDn
    if (-not $pdc) { $ownerDn = 'CN=NTDS Settings,CN=WINDC2,' + $serversDn }
    $fake.ServiceName = $localNtdsDn
    $fake.AddObject(@{
        dn = $localNtdsDn
        guid = '1f9619ff-8b86-d011-b42d-00c04fc964ff'
        sid = 'S-1-5-21-1-2-3-1000'
        object_class = @('top', 'settings')
        admin_count = 0
        primary_group_id = 513
        token_groups = @()
        usn_changed = 1
        delegated = $true
        values = @{ 'objectclass' = @('top', 'nTDSDSA') }
    })

    # the domain head.  A real head has no dNSDomainName (measured on
    # WINDC1 on 2026-11-13): the DNS name comes from the domain DN.
    $fake.AddObject(@{
        dn = $domainDn
        guid = 'af9619ff-8b86-d011-b42d-00c04fc964ff'
        sid = 'S-1-5-21-1-2-3'
        object_class = @('top', 'domain', 'domainDNS')
        maq = 10
        admin_count = 0
        primary_group_id = 512
        token_groups = @()
        usn_changed = 1
        delegated = $true
        values = @{
            'objectclass' = @('top', 'domain', 'domainDNS')
            'fsmoroleowner' = @($ownerDn)
            'ms-ds-machineaccountquota' = @('10')
        }
    })

    # AD exposes the Domain Controllers location as an OU.  There is no
    # synthetic parent attribute.
    $fake.AddObject(@{
        dn = 'OU=Domain Controllers,' + $domainDn
        guid = '2f9619ff-8b86-d011-b42d-00c04fc964ff'
        sid = $null
        sam = $null
        object_class = @('top', 'organizationalUnit')
        admin_count = 0
        member_of = @()
        member = @()
        primary_group_id = 513
        token_groups = @()
        usn_changed = 1
        delegated = $true
        values = @{ 'objectclass' = @('top', 'organizationalUnit') }
    })

    # BUILTIN Administrators, as the lab DC answered it to the Administrator
    # (fixtures/win-dc-admin-r3.json): its SID is outside the domain, so the
    # helper names it privileged from its BUILTIN list.  The GUID is the
    # fake's own; the measured document does not carry one.
    $fake.AddObject(@{
        dn = 'CN=Administrators,CN=Builtin,' + $domainDn
        guid = '5b9619ff-8b86-d011-b42d-00c04fc964ff'
        sid = 'S-1-5-32-544'
        sam = 'Administrators'
        object_class = @('top', 'group')
        admin_count = 1
        member_of = @()
        member = @(
            'CN=Domain Admins,CN=Users,' + $domainDn
            'CN=Enterprise Admins,CN=Users,' + $domainDn
            'CN=Administrator,CN=Users,' + $domainDn
        )
        primary_group_id = $null
        token_groups = @()
        usn_changed = 1
        delegated = $true
        values = @{
            'samaccountname' = @('Administrators')
            'objectclass' = @('top', 'group')
            'admincount' = @('1')
            'grouptype' = @('-2147483643')
            'member' = @(
                'CN=Domain Admins,CN=Users,' + $domainDn
                'CN=Enterprise Admins,CN=Users,' + $domainDn
                'CN=Administrator,CN=Users,' + $domainDn
            )
        }
    })

    # the objects of the case
    $caseObjects = @()
    if ($null -ne $Config['objects']) { $caseObjects = @($Config['objects']) }
    foreach ($object in $caseObjects) {
        if ($null -eq $object) { continue }
        $entry = @{
            dn = [string]$object['dn']
            guid = $null
            sid = $null
            sam = $null
            object_class = @('top', 'person', 'organizationalPerson', 'user')
            admin_count = 0
            member_of = @()
            member = @()
            primary_group_id = 513
            token_groups = @()
            parent = $null
            usn_changed = 1
            delegated = $true
            upn = $null
            values = @{}
        }
        foreach ($key in $object.Keys) { $entry[[string]$key] = $object[$key] }
        $values = @{}
        if ($null -ne $object['sam']) { $values['samaccountname'] = @([string]$object['sam']) }
        if ($null -ne $object['object_class']) { $values['objectclass'] = @($object['object_class']) }
        if ($null -ne $object['uac']) { $values['useraccountcontrol'] = @([string]$object['uac']) }
        if ($null -ne $object['etypes']) { $values['msds-supportedencryptiontypes'] = @([string]$object['etypes']) }
        if ($null -ne $object['lockout']) { $values['lockouttime'] = @([string]$object['lockout']) }
        if ($null -ne $object['maq']) { $values['ms-ds-machineaccountquota'] = @([string]$object['maq']) }
        if ($null -ne $object['admin_count']) { $values['admincount'] = @([string]$object['admin_count']) }
        if ($null -ne $object['member_of']) { $values['memberof'] = @($object['member_of']) }
        if ($null -ne $object['member']) { $values['member'] = @($object['member']) }
        if ($null -ne $object['primary_group_id']) { $values['primarygroupid'] = @([string]$object['primary_group_id']) }
        # tokenGroups is an operational binary attribute and is materialised
        # by Search only for an own-DN base read.  There is no parent attr.
        if ($null -ne $object['usn_changed']) { $values['usnchanged'] = @([string]$object['usn_changed']) }
        if ($null -ne $object['upn']) { $values['userprincipalname'] = @([string]$object['upn']) }
        if ($null -ne $object['values']) {
            foreach ($key in $object['values'].Keys) { $values[[string]$key] = $object['values'][$key] }
        }
        $entry['values'] = $values
        $fake.AddObject($entry)
    }
    return $fake
}

function New-NewtonFakeScheduler {
    # The fake task scheduler: it records the tasks, it runs nothing.
    param($CallLog = $null, [bool]$RegisterError = $false, [bool]$DeleteError = $false)
    $fake = [pscustomobject]@{
        Log = (New-Object System.Collections.ArrayList)
        CallLog = $CallLog
        Tasks = @{}
        RegisterError = $RegisterError
        DeleteError = $DeleteError
    }
    $fake | Add-Member -MemberType ScriptMethod -Name Register -Value {
        param([string]$Name, [string]$StartBoundary, [string]$Arguments)
        [void]$this.Log.Add(('register ' + $Name + ' ' + $StartBoundary + ' ' + $Arguments))
        if ($null -ne $this.CallLog) {
            [void]$this.CallLog.Add('task:register ' + $Name)
        }
        if ($this.RegisterError) { throw (New-Object System.Exception('the task registration failed')) }
        $this.Tasks[$Name] = @{ boundary = $StartBoundary; arguments = $Arguments }
    }
    $fake | Add-Member -MemberType ScriptMethod -Name Delete -Value {
        param([string]$Name)
        [void]$this.Log.Add(('delete ' + $Name))
        if ($null -ne $this.CallLog) {
            [void]$this.CallLog.Add('task:delete ' + $Name)
        }
        if ($this.DeleteError) { throw (New-Object System.Exception('the task deletion failed')) }
        if (-not $this.Tasks.ContainsKey($Name)) {
            throw ([System.Exception]::new('the task does not exist'))
        }
        $this.Tasks.Remove($Name)
    }
    return $fake
}

function New-NewtonFakeStream([System.IO.FileStream]$Inner, [System.Collections.ArrayList]$Log) {
    # The stream of a file of the transaction store.  The fake records
    # the flush to the disk: a record that is in the buffer of the
    # process is a record that a power cut loses, and a test has to be
    # able to see whether the helper flushed it.
    $stream = [PSCustomObject]@{ Inner = $Inner; Log = $Log }
    $stream | Add-Member -MemberType ScriptMethod -Name Write -Value {
        param([byte[]] $Buffer, [int] $Offset, [int] $Count)
        $this.Inner.Write($Buffer, $Offset, $Count)
    }
    $stream | Add-Member -MemberType ScriptMethod -Name Flush -Value {
        param([bool] $ToDisk = $false)
        [void]$this.Log.Add('flush-to-disk ' + $ToDisk)
        $this.Inner.Flush($ToDisk)
    }
    $stream | Add-Member -MemberType ScriptMethod -Name Close -Value {
        $this.Inner.Close()
    }
    $stream | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $this.Inner.Dispose()
    }
    return $stream
}

function New-NewtonFakeFileSystem {
    # The transaction-store file system under the ACL measured on the real
    # DC: an inherited CreateFiles right can create and write a new file, but
    # it cannot reopen an existing file for Write/ReadWrite and has no DELETE
    # right for replace, delete or move.  Read remains allowed.
    param([bool]$LockUnauthorized = $false, [string]$CreateNewCollisionPath = '')
    $fake = [pscustomobject]@{
        LockUnauthorized = $LockUnauthorized
        CreateNewCollisionPath = $CreateNewCollisionPath
        CreateNewCollisionUsed = $false
        Log = (New-Object System.Collections.ArrayList)
    }
    $fake | Add-Member -MemberType ScriptMethod -Name Open -Value {
        param([string]$Path, $Mode, $Access, $Share)
        [void]$this.Log.Add(('open ' + [string]$Mode + ' ' + [string]$Access + ' ' + [string]$Path))
        if ($this.LockUnauthorized -and ([System.IO.Path]::GetFileName($Path) -eq '.lock')) {
            throw ([System.UnauthorizedAccessException]::new('measured tx ACL denies this open'))
        }
        if (($this.CreateNewCollisionPath -ne '') -and
            (-not $this.CreateNewCollisionUsed) -and
            ($Path -ceq $this.CreateNewCollisionPath) -and
            ([string]$Mode -eq [string][System.IO.FileMode]::CreateNew)) {
            [System.IO.File]::WriteAllText($Path, '{"writer":"other"}')
            $this.CreateNewCollisionUsed = $true
            throw ([System.IO.IOException]::new('another writer created the generation first'))
        }
        $exists = [System.IO.File]::Exists($Path)
        $writeAccess = ([string]$Access -eq [string][System.IO.FileAccess]::Write) -or
            ([string]$Access -eq [string][System.IO.FileAccess]::ReadWrite)
        if ($exists -and $writeAccess) {
            throw ([System.UnauthorizedAccessException]::new('measured tx ACL denies an existing-file write'))
        }
        $stream = [System.IO.File]::Open($Path, $Mode, $Access, $Share)
        if (-not $writeAccess) {
            # A stream that is only read is the real one: a reader of the
            # contract takes it as it is.
            return $stream
        }
        return (New-NewtonFakeStream $stream $this.Log)
    }
    $fake | Add-Member -MemberType ScriptMethod -Name ReadAllText -Value {
        param([string]$Path)
        [void]$this.Log.Add(('read ' + $Path))
        return [System.IO.File]::ReadAllText($Path)
    }
    $fake | Add-Member -MemberType ScriptMethod -Name Replace -Value {
        param([string]$Source, [string]$Destination, $Backup)
        [void]$this.Log.Add(('replace ' + $Source + ' ' + $Destination))
        throw ([System.UnauthorizedAccessException]::new('measured tx ACL denies replace'))
    }
    $fake | Add-Member -MemberType ScriptMethod -Name DeleteFile -Value {
        param([string]$Path)
        [void]$this.Log.Add(('delete ' + $Path))
        throw ([System.UnauthorizedAccessException]::new('measured tx ACL denies delete'))
    }
    $fake | Add-Member -MemberType ScriptMethod -Name Move -Value {
        param([string]$Source, [string]$Destination)
        [void]$this.Log.Add(('move ' + $Source + ' ' + $Destination))
        throw ([System.UnauthorizedAccessException]::new('measured tx ACL denies move'))
    }
    return $fake
}
