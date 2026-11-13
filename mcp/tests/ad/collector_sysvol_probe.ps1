# The probe of the SYSVOL scan of the Windows collector.
#
# The collector refuses to be dot-sourced and runs a whole directory scan
# when it is run, so the probe parses it and defines only its functions and
# its script-scope settings.  It then scans the Policies folder it is given
# with Get-PolicyFileResults and writes the files section as one JSON object
# on stdout.
#
#     pwsh -NoProfile -NonInteractive -File collector_sysvol_probe.ps1 <collector.ps1> <Policies folder>

param(
    [Parameter(Mandatory = $true)][string]$CollectorPath,
    [Parameter(Mandatory = $true)][string]$PoliciesPath
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

# One script-scope setting of the collector is the deadline of its run.
$deadlineUtc = [DateTime]::UtcNow.AddSeconds(60)

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($CollectorPath, [ref]$tokens, [ref]$errors)
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

$files = Get-PolicyFileResults $PoliciesPath $deadlineUtc
[Console]::Out.Write(($files | ConvertTo-Json -Depth 12 -Compress) + "`n")
exit 0
