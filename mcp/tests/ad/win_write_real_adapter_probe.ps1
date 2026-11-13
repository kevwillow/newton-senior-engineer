# The probe of the REAL LDAP adapter of the Windows write helper.
#
# The fake of the directory (win_write_fake.ps1) replaces the adapter of the
# helper entirely, so no test of the fake ever runs the real Modify and Add
# methods.  On a real Windows Server 2025 domain controller it was
# measured that the answer of an apply was a JSON list:
#
#     [0,1,{"v":1,"code":"ok","live":{"uac":512},"undo_at":1794247873}]
#
# The cause is the return value of the collection methods of
# System.DirectoryServices.Protocols: DirectoryAttributeModificationCollection
# .Add and DirectoryAttributeCollection.Add return the index of the entry
# they added, and the real adapter did not discard it.
#
# This probe builds the REAL adapter of write.ps1 with its connection
# replaced by an object that records the request and answers nothing, calls
# the real Modify and the real Add, and counts what each of them puts into
# the pipeline.  No host is contacted: the connection is a local object and
# no socket is ever opened.
#
#     pwsh -NoProfile -File win_write_real_adapter_probe.ps1
#
# The answer is one JSON object on stdout.

param()

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $PSCommandPath
$mcpRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $mcpRoot 'newton_mcp/ad/collector/write.ps1')

# The connection of the test: it records every request and answers nothing.
$connection = [pscustomobject]@{
    Requests = (New-Object System.Collections.ArrayList)
}
$connection | Add-Member -MemberType ScriptMethod -Name SendRequest -Value {
    param($Request)
    [void]$this.Requests.Add($Request)
    return $null
}

$adapter = New-NewtonLdapAdapter -Connection $connection

$dn = 'CN=Newton-Probe,OU=Users,DC=win,DC=newton,DC=test'

# one old value and one new value, as an apply of a uac does
$modifyOutput = @(& { $adapter.Modify($dn, 'userAccountControl', @('4260352'), @('66048')) })

# five attributes, as an add of a user does
$attributes = @{
    'cn' = @('Newton-Probe')
    'sAMAccountName' = @('newton-probe')
    'userPrincipalName' = @('newton-probe@win.newton.test')
    'userAccountControl' = @('514')
    'objectClass' = @('top', 'person', 'organizationalPerson', 'user')
}
$addOutput = @(& { $adapter.Add($dn, $attributes) })

$modifyRequest = $null
$addRequest = $null
foreach ($request in $connection.Requests) {
    if ($request -is [System.DirectoryServices.Protocols.ModifyRequest]) { $modifyRequest = $request }
    if ($request -is [System.DirectoryServices.Protocols.AddRequest]) { $addRequest = $request }
}

$modifyCount = 0
if ($null -ne $modifyRequest) { $modifyCount = $modifyRequest.Modifications.Count }
$addCount = 0
if ($null -ne $addRequest) { $addCount = $addRequest.Attributes.Count }

$answer = @{
    modify_output_count = $modifyOutput.Count
    modify_output_types = @($modifyOutput | ForEach-Object { $_.GetType().FullName })
    add_output_count = $addOutput.Count
    add_output_types = @($addOutput | ForEach-Object { $_.GetType().FullName })
    request_count = $connection.Requests.Count
    modify_modifications = $modifyCount
    add_attributes = $addCount
    connection_type = $connection.GetType().Name
}
$json = $answer | ConvertTo-Json -Depth 8 -Compress
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::Out.Write($json + "`n")
exit 0
