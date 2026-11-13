param([Parameter(Mandatory = $true)][string]$HelperPath)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

. $HelperPath

$result = [ordered]@{}
$valid = ConvertFrom-NewtonHex ('11' * 32)
$result['valid_length'] = $valid.Length
$result['valid_first'] = [int]$valid[0]
$result['read_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::Read)
$result['read_execute_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
$result['read_permissions_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::ReadPermissions)
$result['synchronize_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::Synchronize)
$result['write_data_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::WriteData)
$result['append_data_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::AppendData)
$result['write_attributes_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::WriteAttributes)
$result['write_extended_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::WriteExtendedAttributes)
$result['delete_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::Delete)
$result['delete_children_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)
$result['change_permissions_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::ChangePermissions)
$result['take_ownership_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::TakeOwnership)
$result['modify_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::Modify)
$result['full_control_writable'] = Test-NewtonRightsWritable ([Security.AccessControl.FileSystemRights]::FullControl)
foreach ($case in @(
    @{ name = 'odd'; value = 'abc' }
    @{ name = 'non_hex'; value = 'gg' }
    @{ name = 'empty'; value = '' }
    @{ name = 'upper'; value = 'AABB' }
)) {
    try {
        $decoded = ConvertFrom-NewtonHex ([string]$case['value'])
        if (([string]$case['value']) -eq '') {
            $result[[string]$case['name']] = 'accepted'
            continue
        }
        $result[[string]$case['name']] = 'accepted'
    } catch {
        $result[[string]$case['name']] = 'rejected'
    }
}
$result | ConvertTo-Json -Compress

