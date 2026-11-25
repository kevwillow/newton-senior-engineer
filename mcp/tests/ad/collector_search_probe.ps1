# The probe of the search of the Windows AD collector.
#
# The collector runs on a Windows domain controller, where pytest never
# reaches it, so this probe parses it, defines only its functions and its
# script-scope settings, and runs one query against a fake searcher.  The
# fake raises the COM error the probe is given, either where the search
# starts (the bind of the search root) or where a row that came back is
# read; the mode "ok" raises nothing and reads the row.
#
#     pwsh -NoProfile -NonInteractive -File collector_search_probe.ps1 <collector.ps1> <search|row|ok> <hresult>
#
# The status, the error code and the number of rows of the query are
# written as one JSON object on stdout.

param(
    [Parameter(Mandatory = $true)][string]$CollectorPath,
    [Parameter(Mandatory = $true)][ValidateSet('search', 'row', 'ok')][string]$Where,
    [Parameter(Mandatory = $true)][string]$HResult
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

# The fakes of the searcher and of a row.  The properties of a row carry
# an indexer, and a PowerShell class has none, so the fakes are written
# in C# the way the fake of the write helper is.
if ($null -eq ('NewtonFakeSearcher' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public sealed class NewtonFakeProperties {
    public string[] PropertyNames { get; set; }
    public Hashtable Values { get; set; }
    public string ThrowOn { get; set; }
    public int ThrowCode { get; set; }

    public object this[string name] {
        get {
            if (!string.IsNullOrEmpty(ThrowOn) && name == ThrowOn) {
                throw new COMException("the fake directory service", ThrowCode);
            }
            return Values[name];
        }
    }
}

public sealed class NewtonFakeSearchResult {
    public object Properties { get; set; }
    public string Path { get; set; }
}

public sealed class NewtonFakeSearcher {
    public object SearchRoot { get; set; }
    public string Filter { get; set; }
    public object SearchScope { get; set; }
    public int PageSize { get; set; }
    public int SizeLimit { get; set; }
    public object ServerTimeLimit { get; set; }
    public List<string> PropertiesToLoad { get; set; }
    public object SecurityMasks { get; set; }
    public string ThrowWhere { get; set; }
    public int ThrowCode { get; set; }
    public object[] Rows { get; set; }

    public object[] FindAll() {
        if (ThrowWhere == "search") {
            throw new COMException("the fake directory service", ThrowCode);
        }
        return Rows;
    }
}
'@
}

# System.DirectoryServices is a Windows assembly: the probe declares the
# two enumerations the collector names, so the script runs anywhere.
if ($null -eq ('System.DirectoryServices.SearchScope' -as [type])) {
    Add-Type -TypeDefinition @'
namespace System.DirectoryServices {
    public enum SearchScope { Base = 0, OneLevel = 1, Subtree = 2 }
    [System.Flags]
    public enum SecurityMasks { None = 0, Owner = 1, Group = 2, Dacl = 4, Sacl = 8 }
}
'@
}

# The COM error the fake raises, the way the directory service raises it:
# the HRESULT of the error, as a signed 32 bit number.
$script:FakeCode = [BitConverter]::ToInt32(
    [BitConverter]::GetBytes([Convert]::ToUInt32($HResult, 16)), 0)

# One script-scope setting of the collector is the deadline of its run.
$deadlineUtc = [DateTime]::UtcNow.AddSeconds(60)

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $CollectorPath, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) {
    [Console]::Error.WriteLine('the collector does not parse')
    exit 3
}
foreach ($statement in $ast.EndBlock.Statements) {
    $isFunction = $statement -is [System.Management.Automation.Language.FunctionDefinitionAst]
    $isSetting = ($statement -is [System.Management.Automation.Language.AssignmentStatementAst]) -and
        ($statement.Left.Extent.Text -like '$script:*')
    if ($isFunction -or $isSetting) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}
$script:DeadlineUtc = $deadlineUtc

# The searcher and the entry the collector builds.  The collector asks
# New-Object for both, and the probe answers with the fakes.
$script:FakeEntry = [pscustomobject]@{ Path = '' }
$script:FakeSearcher = [NewtonFakeSearcher]::new()
$script:FakeSearcher.ThrowWhere = $Where
$script:FakeSearcher.ThrowCode = $script:FakeCode
$script:FakeSearcher.PropertiesToLoad = [System.Collections.Generic.List[string]]::new()

if ($Where -ne 'search') {
    $properties = [NewtonFakeProperties]::new()
    $properties.PropertyNames = @(
        'msDS-MinimumPasswordLength', 'msDS-LockoutThreshold', 'distinguishedName')
    $properties.Values = @{
        'msDS-MinimumPasswordLength' = @('4')
        'msDS-LockoutThreshold' = @('0')
        'distinguishedName' = @(
            'CN=Password Settings Container,CN=System,DC=win,DC=newton,DC=test')
    }
    if ($Where -eq 'row') {
        $properties.ThrowOn = 'msDS-MinimumPasswordLength'
        $properties.ThrowCode = $script:FakeCode
    }
    $row = [NewtonFakeSearchResult]::new()
    $row.Properties = $properties
    $row.Path = 'LDAP://dc.win.newton.test/CN=Password Settings Container,' +
        'CN=System,DC=win,DC=newton,DC=test'
    $script:FakeSearcher.Rows = @($row)
}

function New-Object {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][string]$TypeName,
        [Parameter(Position = 1)][object[]]$ArgumentList
    )
    if ($TypeName -eq 'System.DirectoryServices.DirectorySearcher') {
        return $script:FakeSearcher
    }
    if ($TypeName -eq 'System.DirectoryServices.DirectoryEntry') {
        return $script:FakeEntry
    }
    if ($null -eq $ArgumentList) {
        return ,(Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName)
    }
    return ,(Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName `
        -ArgumentList $ArgumentList)
}

# The query of the packet: the fine-grained password policies, whose
# search root the ordinary account may not read.
$query = [pscustomobject]@{
    id = 'psos'
    base = 'CN=Password Settings Container,CN=System,{domain}'
    filter = '(objectClass=*)'
    scope = 'base'
    attrs = @('msDS-MinimumPasswordLength', 'msDS-LockoutThreshold')
    sd = $false
    limit = 1000
}
$context = @{
    domain_dn = 'DC=win,DC=newton,DC=test'
    config_dn = 'CN=Configuration,DC=win,DC=newton,DC=test'
    schema_dn = 'CN=Schema,CN=Configuration,DC=win,DC=newton,DC=test'
    dns_host = 'dc.win.newton.test'
    domain_dns = 'win.newton.test'
}

$result = Invoke-CollectorQuery $query $context
$block = $result
if ($block -is [array]) { $block = $block[0] }
$out = [ordered]@{
    status = [string]$block['status']
    error_code = [string]$block['error_code']
    rows = @($block['rows']).Count
}
[Console]::Out.Write(($out | ConvertTo-Json -Depth 4 -Compress) + "`n")
exit 0
