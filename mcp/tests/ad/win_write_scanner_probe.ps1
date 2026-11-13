param([Parameter(Mandatory = $true)][string]$HelperPath)

# The probe of the JSON scanner of the Windows write helper.
#
# It answers three facts:
#   - a nesting of 31 arrays is accepted and a nesting of 32 is refused;
#   - the scan of 64 KiB of brackets is linear: it finishes in a second;
#   - a request that is nested too deep is a schema.

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

. $HelperPath

function New-NestedText {
    # A JSON object whose value is an array nested as deep as asked.
    param([int]$Depth)
    return ('{"a":' + ('[' * $Depth) + '1' + (']' * $Depth) + '}')
}

$result = [ordered]@{}
$result['depth_31_accepted'] = (Test-NewtonJsonText -Text (New-NestedText 31))
$result['depth_32_refused'] = (-not (Test-NewtonJsonText -Text (New-NestedText 32)))

$brackets = New-Object string ([char]'[', 65536)
$watch = [System.Diagnostics.Stopwatch]::StartNew()
$result['brackets_accepted'] = (Test-NewtonJsonText -Text $brackets)
$watch.Stop()
$result['brackets_ms'] = [int]$watch.ElapsedMilliseconds

$nested = '{"a":' + (New-Object string ([char]'[', 65535))
$watch = [System.Diagnostics.Stopwatch]::StartNew()
$result['nested_accepted'] = (Test-NewtonJsonText -Text $nested)
$watch.Stop()
$result['nested_ms'] = [int]$watch.ElapsedMilliseconds

$code = ''
try {
    $null = ConvertFrom-NewtonRequest -Raw $nested
    $code = 'ok'
} catch {
    $code = Get-NewtonRefusalCode $_
}
$result['deep_request_code'] = $code

$result | ConvertTo-Json -Compress
