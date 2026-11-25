"""The bootstrap of one build server (PLAN-1.5 task 4, DESIGN-1.5 "The bootstrap").

The bootstrap is the script the owner runs once on a fresh server.
Everything it writes is checked here: the golden render, the block of
the build account and the two global settings of the sshd
configuration, the order of the steps, the firewall rule, the Proxmox
variant, the access control list of the key and of the password file,
and the values of the plan that reach the script.

The values are fed to the renderer raw: a value that came from
anywhere else has to stay inside its single-quoted string, and the
script has to stay a valid PowerShell script.  The parser of pwsh
answers both questions: it parses the script and it names the commands
of it.
"""

from __future__ import annotations

import base64
import copy
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp import approve
from newton_mcp.ad.build import bootstrap
from newton_mcp.ad.build import plan
from ops_fixture import OPS  # type: ignore[import-not-found]

from pwsh_path import PWSH


#: The bytes of the build helper of the tests: the helper of the
#: package is written by task 3, and the tests of the bootstrap need a
#: helper of their own to pin the render.
HELPER_BYTES = b"# Newton's AD build helper (the fixture of the bootstrap tests).\n"

#: The plan of the tests: one domain, one server, one baseline option
#: and one accepted finding.  Every value is synthetic.
GOLDEN_INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "ad-build.test",
        "netbios": "ADBUILD",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers", "IT/Workstations"],
        "groups": ["IT Admins", "IT Operators"],
        "owner_admin": "owner-admin",
    },
    "servers": [
        {
            "device": "build1",
            "role": "dc1",
            "hostname": "DC1",
            "ip": "192.0.2.11",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "forwarders": ["192.0.2.53"],
            "checkpoint": "hyperv",
        }
    ],
    "baseline": {
        "version": "2026.11",
        "options": {"administrator": "random-password"},
    },
    "accepted_findings": [
        {"id": "AD-A-51", "reason": "owner-accepted"},
    ],
    "ops": dict(OPS),
}

#: The Proxmox variant of the plan of the tests.
PROXMOX_INPUTS: dict[str, Any] = copy.deepcopy(GOLDEN_INPUTS)
PROXMOX_INPUTS["servers"][0] = {
    "device": "build1",
    "role": "dc1",
    "hostname": "DC1",
    "ip": "192.0.2.11",
    "prefix": 24,
    "gateway": "192.0.2.1",
    "forwarders": ["192.0.2.53"],
    "checkpoint": "proxmox",
    "vmgenid": "44387c6b-1f2e-4a5b-8c9d-0e1f2a3b4c5d",
    "agent": 1,
}

#: The sshd configuration of a Server 2025, with the two settings the
#: bootstrap changes left as they are.
FAKE_SSHD_CONFIG = (
    "# sshd_config\n"
    "Port 22\n"
    "#ListenAddress 0.0.0.0\n"
    "#PasswordAuthentication yes\n"
    "#KbdInteractiveAuthentication yes\n"
    "AuthorizedKeysFile .ssh/authorized_keys\n"
    "Subsystem sftp sftp-server\n"
    "Match Group administrators\n"
    "       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n"
)

#: The golden render of the bootstrap of the plan of the tests.
GOLDEN = r"""# Newton's Active Directory build bootstrap.
#
# Read this script, then run it as an Administrator on the fresh
# server, at the server's console or in an interactive ssh session (ssh -tt).
# It asks for the passphrase of the build with Read-Host, which needs a
# console and hangs when stdin is a pipe.  It is the only step Newton asks
# of the owner: after it the build account logs in over SSH with its key,
# and the session runs the build helper and nothing else.
#
# The password of the build account is random, is never shown and is
# never stored in clear: it is in a DPAPI file of the machine that
# only SYSTEM and the Administrators may read.  The key of the server
# is in the install root of the helper, and only SYSTEM and the
# Administrators may read that either.
param(
    [string]$PublicKey = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$BuildDir = 'C:\NewtonBuild'
$PasswordFile = 'C:\NewtonBuild\pw.bin'
$InstallRoot = 'C:\ProgramData\Newton\ad-build'
$KeyFile = 'C:\ProgramData\Newton\ad-build\key.hex'
$DeviceFile = 'C:\ProgramData\Newton\ad-build\device.txt'
$HelperFile = 'C:\ProgramData\Newton\ad-build\build.ps1'
$KeysFile = 'C:\NewtonBuild\authorized_keys'
$SshdConfig = 'C:\ProgramData\ssh\sshd_config'
$SshdBackup = 'C:\ProgramData\ssh\sshd_config.bak-newton-build'
$BuildUser = 'newton-build'
$RestartTask = 'Newton AD build sshd restart'
$Device = 'build1'
$HostName = 'DC1'
$Domain = 'ad-build.test'

function Protect-NewtonPath {
    # The access control list of one path of the build: Administrators
    # and SYSTEM have full control and nobody else.  The rule of the
    # parent is not inherited, so a file of the build directory is not
    # readable by the other users of the server.
    param([string]$Path, [string]$Inheritance)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $flags = [System.Security.AccessControl.InheritanceFlags]$Inheritance
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    $acl.SetOwner($administratorsSid)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administratorsSid, $full, $flags, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, $full, $flags, $none, $allow)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-ApprovalKeyHex([string]$Passphrase, [string]$DeviceName) {
    # The approval key K: PBKDF2-HMAC-SHA256, the UTF-8 bytes of the
    # passphrase, the salt "newton-approve-v1:" and the device, 600000
    # iterations, 32 bytes.  It is the same key the Newton host derives
    # with derive_k.
    $salt = [System.Text.Encoding]::UTF8.GetBytes('newton-approve-v1:' + $DeviceName)
    $password = [System.Text.Encoding]::UTF8.GetBytes($Passphrase)
    try {
        $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $bytes = $derive.GetBytes(32)
        return (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
    } finally {
        [Array]::Clear($password, 0, $password.Length)
    }
}

function Get-ApprovalFingerprintHex([string]$KeyHex) {
    # The fingerprint of the key: HMAC-SHA256 of the constant message,
    # keyed with the 32 bytes of K.  It is the value the Newton host
    # compares with the one it printed.
    $key = New-Object 'System.Byte[]' ($KeyHex.Length / 2)
    for ($index = 0; $index -lt $key.Length; $index++) {
        $key[$index] = [System.Convert]::ToByte($KeyHex.Substring($index * 2, 2), 16)
    }
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
    try {
        $bytes = $hmac.ComputeHash([System.Text.Encoding]::ASCII.GetBytes('newton-approval-fingerprint-v1'))
        return (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
    } finally {
        [Array]::Clear($key, 0, $key.Length)
    }
}

Write-Host 'Step 1: the pre-checks'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'this script must run elevated, as an Administrator'
}

Write-Host 'Step 2: OpenSSH and the sshd configuration'
$capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
if ($capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
    Write-Host 'The OpenSSH server is installed.'
} else {
    Write-Host 'The OpenSSH server is installed already.'
}
$service = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
if (-not $service) { throw 'the sshd service is missing' }
Set-Service -Name 'sshd' -StartupType Automatic
if ($service.Status -ne 'Running') {
    Start-Service -Name 'sshd'
    Write-Host 'sshd was started once, so that its configuration file exists.'
} else {
    Write-Host 'sshd is running.'
}
if (-not (Test-Path -LiteralPath $SshdConfig)) { throw 'the sshd configuration is missing' }
if (-not (Test-Path -LiteralPath $SshdBackup)) {
    Copy-Item -LiteralPath $SshdConfig -Destination $SshdBackup -Force
    Write-Host 'The sshd configuration is backed up once, as .bak-newton-build.'
}

Write-Host 'Step 3: the build account'
# Windows PowerShell 5.1 does not load the DPAPI type by itself
# (measured on BUILD1, 2026-11-18).
Add-Type -AssemblyName System.Security
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
# The directory is protected before the password is written in it: a
# file of it inherits the rule of the directory.
Protect-NewtonPath -Path $BuildDir -Inheritance 'ContainerInherit, ObjectInherit'
$account = Get-LocalUser -Name $BuildUser -ErrorAction SilentlyContinue
if (-not $account) {
    # The password is made of 32 random bytes, and it is never shown
    # and never stored in clear: it goes into the DPAPI file of the
    # machine and nowhere else.
    $random = New-Object 'System.Byte[]' 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($random) } finally { $generator.Dispose() }
    $password = [System.Convert]::ToBase64String($random)
    $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
    New-LocalUser -Name $BuildUser -Password $secure -AccountNeverExpires -PasswordNeverExpires -Description 'Newton AD build account' | Out-Null
    # UTF-8: the bytes the helper decodes (Get-NewtonBuildPassword).
    $plain = [System.Text.Encoding]::UTF8.GetBytes($password)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect($plain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [System.IO.File]::WriteAllBytes($PasswordFile, $protected)
    [System.Array]::Clear($plain, 0, $plain.Length)
    $password = $null
    $secure = $null
    Write-Host 'The build account is created with a random password. It was not shown and it is not stored in clear.'
} else {
    # The password of the account was never shown and is nowhere else
    # than in the file of the machine: an account without that file is
    # an account nobody can log in with.
    if (-not (Test-Path -LiteralPath $PasswordFile)) {
        throw 'the build account exists and its password file is missing; remove the account and run this script again'
    }
    Write-Host 'The build account exists. Its password is left alone.'
}
# The account is in the local Administrators: the sshd configuration of
# a Server 2025 admits the administrators and the OpenSSH users, and
# the account has to be in one of the two.
$administrators = Get-LocalGroup -Name 'Administrators'
$members = @(Get-LocalGroupMember -Group $administrators -ErrorAction SilentlyContinue)
$isMember = $false
foreach ($member in $members) {
    if ([string]$member.Name -like ('*\' + $BuildUser)) { $isMember = $true }
}
if (-not $isMember) {
    Add-LocalGroupMember -Group $administrators -Member $BuildUser
    Write-Host 'The build account is in the local Administrators group.'
}
$openSshUsers = Get-LocalGroup -Name 'OpenSSH Users' -ErrorAction SilentlyContinue
if ($openSshUsers) {
    $openSshMembers = @(Get-LocalGroupMember -Group $openSshUsers -ErrorAction SilentlyContinue)
    $inOpenSsh = $false
    foreach ($member in $openSshMembers) {
        if ([string]$member.Name -like ('*\' + $BuildUser)) { $inOpenSsh = $true }
    }
    if (-not $inOpenSsh) {
        Add-LocalGroupMember -Group $openSshUsers -Member $BuildUser
        Write-Host 'The build account is in the local OpenSSH Users group.'
    }
}

Write-Host 'Step 4: the keys file'
# The keys file is written on every run: a key that is in it already,
# and that this run was not given, is not kept.
if ($PublicKey) {
    # One key line: the type, the base64 body and an optional comment,
    # which is dropped because it is not part of the key.
    $keyLine = $PublicKey.Trim()
    if (-not ($keyLine -cmatch '^(ssh-(?:ed25519|rsa)) ([A-Za-z0-9+/]+={0,3})(?: [^\r\n]*)?$')) {
        throw 'the public key is not one key line'
    }
    $keyType = $Matches[1]
    $keyBody = $Matches[2]
    # The body is a sequence of length-prefixed fields and the first one
    # is the type of the key: a body that carries another type than the
    # one of the line is refused, as setupgen refuses it.
    try {
        $keyBlob = [System.Convert]::FromBase64String($keyBody)
    } catch {
        throw 'the body of the public key is not base64'
    }
    $embeddedType = ''
    if ($keyBlob.Length -ge 4) {
        $fieldLength = ([int]$keyBlob[0] -shl 24) -bor ([int]$keyBlob[1] -shl 16) -bor ([int]$keyBlob[2] -shl 8) -bor [int]$keyBlob[3]
        if (($fieldLength -ge 0) -and ($fieldLength -le ($keyBlob.Length - 4))) {
            $embeddedType = [System.Text.Encoding]::ASCII.GetString($keyBlob, 4, $fieldLength)
        }
    }
    if ($embeddedType -cne $keyType) {
        throw 'the body of the public key carries another key type than its line'
    }
    [System.IO.File]::WriteAllText($KeysFile, ('restrict ' + $keyType + ' ' + $keyBody) + "`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Host 'The public key of the build is in the keys file, with the restrict option.'
} else {
    [System.IO.File]::WriteAllText($KeysFile, '', (New-Object System.Text.UTF8Encoding($false)))
    Write-Host 'No public key was given: the keys file is empty. Put the public key of the build in it before the first login.'
}

Write-Host 'Step 5: the build helper and the key of the server'
# The install root of the helper holds the helper, K, the device name and
# the journal.  It is protected before K is written in it: a file of it
# inherits the rule of the directory.
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
Protect-NewtonPath -Path $InstallRoot -Inheritance 'ContainerInherit, ObjectInherit'
$helperB64 = @(
'IyBOZXd0b24ncyBBRCBidWlsZCBoZWxwZXIgKHRoZSBmaXh0dXJlIG9mIHRoZSBib290c3RyYXAgdGVzdHMpLgo='
)
$helperB64 = $helperB64 -join ''
[System.IO.File]::WriteAllBytes($HelperFile, [System.Convert]::FromBase64String($helperB64))
# The helper finds this server in the plan by its device name.
[System.IO.File]::WriteAllText($DeviceFile, $Device + "`n", (New-Object System.Text.UTF8Encoding($false)))
# DC1's helper fills the build templates of the 1.3 and 1.4 setups at
# stage 8 (the maintainer's decision on open point 34): the generators' own templates.
$s8AuditB64 = @(
'IyBzdGFnZSA4IGF1ZGl0IHRlbXBsYXRlIHN0dWIK'
)
$s8AuditB64 = $s8AuditB64 -join ''
[System.IO.File]::WriteAllBytes((Join-Path $InstallRoot 's8-audit.tmpl.ps1'), [System.Convert]::FromBase64String($s8AuditB64))
$s8OpsB64 = @(
'IyBzdGFnZSA4IG9wcyB0ZW1wbGF0ZSBzdHViCg=='
)
$s8OpsB64 = $s8OpsB64 -join ''
[System.IO.File]::WriteAllBytes((Join-Path $InstallRoot 's8-ops.tmpl.ps1'), [System.Convert]::FromBase64String($s8OpsB64))
# The 1.4 write helper that stage 8 sets up for newton-ops. No request of the
# build carries it (the maintainer's decision of 2026-11-19): Windows PowerShell 5.1 under
# OpenSSH hangs reading stdin past about 70 KB, and the helper is bigger. Only
# SYSTEM and the Administrators may change it; stage 8 checks it first.
$WriteHelperFile = 'C:\ProgramData\Newton\ad-build\s8-write.ps1'
$s8WriteB64 = @(
'IyBzdGFnZSA4IHdyaXRlIGhlbHBlciBzdHViCg=='
)
$s8WriteB64 = $s8WriteB64 -join ''
[System.IO.File]::WriteAllBytes($WriteHelperFile, [System.Convert]::FromBase64String($s8WriteB64))
Protect-NewtonPath -Path $WriteHelperFile -Inheritance 'None'
$writeHelperSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $WriteHelperFile).Hash.ToLowerInvariant()
Write-Host ('The write helper of stage 8 is in ' + $WriteHelperFile + '. Only SYSTEM and the Administrators can change it.')
Write-Host ('Its sha256 is ' + $writeHelperSha + '. It must be the plan''s write_helper_sha256, which newton-approve prints.')
Write-Host 'Stage 8 checks it against the plan before anything runs. If it is missing or changed, stage 8 stops: run this bootstrap again.'

# The passphrase is asked here, on the server, twice, and it is never
# echoed.  The secure string is marshalled once and the memory it came
# from is cleared right after.
Write-Host "The next two prompts need a console: run this script at the server's console or in an interactive ssh session (ssh -tt)."
$secure = Read-Host -AsSecureString -Prompt ('approval passphrase for ' + $Device)
$secureAgain = Read-Host -AsSecureString -Prompt 'approval passphrase again'
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$bstrAgain = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAgain)
try {
    $passphrase = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $passphraseAgain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrAgain)
} finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrAgain)
    $secure.Dispose()
    $secureAgain.Dispose()
}
if (-not $passphrase) {
    throw 'the approval passphrase must not be empty'
}
if ($passphrase -ne $passphraseAgain) {
    throw 'the two approval passphrases do not match'
}
$keyHex = Get-ApprovalKeyHex $passphrase $Device
$fingerprint = Get-ApprovalFingerprintHex $keyHex
$passphrase = $null
$passphraseAgain = $null

# The key of the server is written in the install root of the helper,
# and only SYSTEM and the Administrators may read it there.  The key itself is
# never printed: the fingerprint is.
[System.IO.File]::WriteAllText($KeyFile, $keyHex, (New-Object System.Text.UTF8Encoding($false)))
$keyHex = $null
Write-Host ('The key of the server is installed. Its fingerprint is ' + $fingerprint)
Write-Host 'Compare that fingerprint with the one the Newton host printed.'

Write-Host 'Step 6: the access control list'
Protect-NewtonPath -Path $BuildDir -Inheritance 'ContainerInherit, ObjectInherit'
Protect-NewtonPath -Path $PasswordFile -Inheritance 'None'
Protect-NewtonPath -Path $InstallRoot -Inheritance 'ContainerInherit, ObjectInherit'
Protect-NewtonPath -Path $KeyFile -Inheritance 'None'
Protect-NewtonPath -Path $DeviceFile -Inheritance 'None'
Protect-NewtonPath -Path $HelperFile -Inheritance 'None'
Protect-NewtonPath -Path $KeysFile -Inheritance 'None'
Write-Host 'The build directory, the install root of the helper and their files are protected: Administrators and SYSTEM have full control and nobody else.'

Write-Host 'Step 7: the sshd configuration'
# The configuration is built from the backup that step 2 made once, and
# not from the live file: a second run, for the same plan or another
# one, writes the same bytes as the first run of that plan.
$raw = Get-Content -LiteralPath $SshdBackup -Raw
$lines = New-Object System.Collections.Generic.List[string]
foreach ($line in ($raw -split "`r?`n")) { [void]$lines.Add([string]$line) }
# The empty lines at the end are trimmed, so that a run adds no blank
# line at the end of the file.
while (($lines.Count -gt 0) -and ([string]$lines[$lines.Count - 1] -eq '')) { $lines.RemoveAt($lines.Count - 1) }
$firstMatch = -1
$administratorsBlock = -1
for ($index = 0; $index -lt $lines.Count; $index++) {
    $line = [string]$lines[$index]
    if (($firstMatch -lt 0) -and ($line -match '^\s*Match\s')) { $firstMatch = $index }
    if (($administratorsBlock -lt 0) -and ($line -match '^\s*Match\s+Group\s+administrators')) { $administratorsBlock = $index }
}
# The two global settings: a setting behind a Match block is the
# setting of that block, so they are set before the first one.
$globalSettings = @('PasswordAuthentication no', 'KbdInteractiveAuthentication no')
foreach ($setting in $globalSettings) {
    $name = ($setting -split ' ')[0]
    $limit = $lines.Count
    if ($firstMatch -ge 0) { $limit = $firstMatch }
    $found = -1
    for ($index = 0; $index -lt $limit; $index++) {
        if ([string]$lines[$index] -match ('^\s*#?\s*' + $name + '\s+\S+')) { $found = $index; break }
    }
    if ($found -ge 0) {
        $lines[$found] = $setting
    } else {
        $at = $firstMatch
        if ($at -lt 0) { $at = $lines.Count }
        $lines.Insert($at, $setting)
        if ($firstMatch -ge 0) { $firstMatch = $firstMatch + 1 }
        if ($administratorsBlock -ge 0) { $administratorsBlock = $administratorsBlock + 1 }
    }
}
# The block of the build account: it is written ahead of the block of
# the administrators, because every matching block applies and the first
# value of each keyword wins, so its AuthorizedKeysFile must come first.
$block = @(
    '# newton-ad build'
    'Match User newton-build,adbuild\newton-build'
    '    AuthorizedKeysFile C:/NewtonBuild/authorized_keys'
    '    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Newton\ad-build\build.ps1'
    '    PermitTTY no'
    '    AllowTcpForwarding no'
    '    PermitTunnel no'
    '    X11Forwarding no'
    '    AllowAgentForwarding no'
)
# The backup is the configuration before any run of the script, so it
# holds no block of the build account: a backup that holds one is not
# that configuration, and the script stops rather than keep a stale
# block.
foreach ($line in $lines) {
    if ([string]$line -eq '# newton-ad build') {
        throw 'the backup of the sshd configuration holds the block of the build account; put the original configuration back in the backup'
    }
}
$at = $administratorsBlock
if ($at -lt 0) { $at = $lines.Count }
for ($offset = $block.Count - 1; $offset -ge 0; $offset--) {
    $lines.Insert($at, $block[$offset])
}
# A line of the block that holds a line break would be two lines of
# the configuration, and the second one would be a setting of sshd.
foreach ($blockLine in $block) {
    if ($blockLine -match '[\r\n]') { throw 'the block of the build account holds a line break' }
}
# The file is written only when the new configuration differs from the
# bytes of the current file; sshd is restarted at the end of every run.
$newBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((($lines -join "`n") + "`n"))
$oldBytes = [System.IO.File]::ReadAllBytes($SshdConfig)
$sshdChanged = ([System.Convert]::ToBase64String($newBytes) -ne [System.Convert]::ToBase64String($oldBytes))
if ($sshdChanged) {
    [System.IO.File]::WriteAllBytes($SshdConfig, $newBytes)
    Write-Host 'The block of the build account is in the sshd configuration and the password authentication is off.'
} else {
    Write-Host 'The sshd configuration holds the block of the build account already and the password authentication is off.'
}

Write-Host 'Step 8: the sshd check'
$sshdExe = $null
$sshdCommand = Get-Command sshd.exe -ErrorAction SilentlyContinue
if ($sshdCommand) { $sshdExe = $sshdCommand.Source }
if (-not $sshdExe) {
    $candidate = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
    if (Test-Path -LiteralPath $candidate) { $sshdExe = $candidate }
}
if (-not $sshdExe) {
    Copy-Item -LiteralPath $SshdBackup -Destination $SshdConfig -Force
    throw 'sshd.exe was not found. The sshd configuration was put back.'
}
$sshdExit = 0
try {
    & $sshdExe -t
    $sshdExit = $LASTEXITCODE
} catch {
    $sshdExit = 1
}
if ($sshdExit -ne 0) {
    Copy-Item -LiteralPath $SshdBackup -Destination $SshdConfig -Force
    throw 'sshd refused the configuration. The configuration was put back.'
}
Write-Host 'sshd accepted the configuration.'

Write-Host 'Step 9: the SSH firewall rule'
# The rule of a fresh server holds the profile of the network it is
# on, and the network of a build is often a public one: the rule
# holds the profile Any, so that the port 22 is open on it.
$rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -Profile Any | Out-Null
    Write-Host 'The SSH firewall rule is created with the profile Any.'
} else {
    Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Profile Any -Enabled True
    Write-Host 'The SSH firewall rule has the profile Any.'
}

Write-Host 'Step 10: the sshd restart'
Unregister-ScheduledTask -TaskName $RestartTask -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Restart-Service sshd -Force; Unregister-ScheduledTask -TaskName ''Newton AD build sshd restart'' -Confirm:$false"'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(8)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $RestartTask -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Host 'A one-shot SYSTEM task restarts sshd in 8 seconds, whether or not the configuration changed, so that a re-run picks it up. The session ends then.'
Write-Host 'The task removes itself once it has restarted sshd.'
Write-Host ''
Write-Host ('The build account is ' + $BuildUser + ' of ' + $HostName + ' of ' + $Domain + ' on ' + $Device + '.')
Write-Host 'Its password was not shown and it is not stored in clear: it is in the DPAPI file of the machine.'
Write-Host ('The key of the server is in ' + $KeyFile + ', the helper in ' + $HelperFile + ' and the keys file in ' + $KeysFile + '.')
Write-Host 'Newton logs in as the build account with its key, and the session runs the helper and nothing else.'
Write-Host "Before the build starts, set the server's DNS client to a resolver that answers before stage 0; stage 0 refuses a DNS check that gets no answer."
"""

#: The values that a template must not be able to break out of.
HOSTILE_VALUES = [
    "nb'; Write-Host 'pwned' #",
    "nb`; Write-Host `pwned",
    "nb$(Get-Process)",
    "nb`$(Get-Process)",
    "nb\nWrite-Host 'pwned'",
    "nb; Remove-Item -Recurse -Force C:\\",
    'nb"; Write-Host "pwned',
    "nb`nWrite-Host 'pwned",
    "nb`$(Get-Process);#",
    "nb';`nWrite-Host 'pwned' #",
    # PowerShell also ends a single-quoted string at the four Unicode
    # single quotes U+2018, U+2019, U+201A and U+201B.
    "nb\u2019; Write-Host PWNED-INJECTED; \u2019",
    "nb\u2018; Write-Host PWNED-INJECTED; \u2018",
    "nb\u201a; Write-Host PWNED-INJECTED; \u201b",
]


# --------------------------------------------------------------------------
# The fixtures
# --------------------------------------------------------------------------


@pytest.fixture(name="helper")
def _helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The build helper of the package, as a file of the test."""
    path = tmp_path / "build.ps1"
    path.write_bytes(HELPER_BYTES)
    monkeypatch.setattr(bootstrap, "HELPER_PATH", path)
    monkeypatch.setattr(bootstrap, "stage8_templates", lambda: dict(STAGE8_STUBS))
    monkeypatch.setattr(bootstrap, "stage8_write_helper", lambda: STAGE8_WRITE_HELPER_STUB)
    return path


#: The stage 8 templates of the golden render: stubs, so the golden stays
#: short (the real templates are checked below).
STAGE8_STUBS = {
    "s8-audit.tmpl.ps1": b"# stage 8 audit template stub\n",
    "s8-ops.tmpl.ps1": b"# stage 8 ops template stub\n",
}

#: The write helper of the golden render: a stub, as the templates are.
STAGE8_WRITE_HELPER_STUB = b"# stage 8 write helper stub\n"


@pytest.fixture(name="golden_plan")
def _golden_plan() -> dict[str, Any]:
    """The plan of the tests."""
    return plan.plan_build(GOLDEN_INPUTS)


@pytest.fixture(name="proxmox_plan")
def _proxmox_plan() -> dict[str, Any]:
    """The Proxmox plan of the tests."""
    return plan.plan_build(PROXMOX_INPUTS)


def _render(the_plan: dict[str, Any], server: Any = "dc1") -> str:
    """The bootstrap of one server of a plan."""
    return bootstrap.render_bootstrap(the_plan, server)


# --------------------------------------------------------------------------
# The golden render
# --------------------------------------------------------------------------


def test_the_golden_render_is_pinned(helper: Path, golden_plan: dict[str, Any]) -> None:
    assert _render(golden_plan) == GOLDEN


def test_the_role_and_the_server_render_the_same_script(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    by_role = _render(golden_plan, "dc1")
    by_server = _render(golden_plan, golden_plan["servers"][0])
    assert by_role == by_server


# --------------------------------------------------------------------------
# The block of the build account
# --------------------------------------------------------------------------


def test_the_match_line_holds_the_account_and_the_netbios_in_lower_case(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert "Match User newton-build,adbuild\\newton-build" in script


def test_the_netbios_of_the_plan_is_written_in_lower_case(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["netbios"] = "AdBuIlD"
    script = _render(plan.plan_build(inputs))
    assert "Match User newton-build,adbuild\\newton-build" in script
    assert "AdBuIlD" not in script


def test_the_forced_command_runs_the_helper(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert (
        "    ForceCommand powershell.exe -NoProfile -NonInteractive "
        "-ExecutionPolicy Bypass -File C:\\ProgramData\\Newton\\ad-build\\build.ps1"
    ) in script


def test_the_block_refuses_a_terminal_and_a_forwarding(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert "    PermitTTY no" in script
    assert "    AllowTcpForwarding no" in script
    assert "    PermitTunnel no" in script
    assert "    X11Forwarding no" in script
    assert "    AllowAgentForwarding no" in script


def test_the_keys_file_of_the_account_is_named_by_the_block(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert "    AuthorizedKeysFile C:/NewtonBuild/authorized_keys" in script


# --------------------------------------------------------------------------
# The configuration of sshd, run under pwsh
# --------------------------------------------------------------------------


def _step(script: str, number: int) -> str:
    """The lines of one step of the script."""
    lines = script.split("\n")
    start: int | None = None
    end = len(lines)
    for index, line in enumerate(lines):
        if line.startswith(f"Write-Host 'Step {number}:"):
            start = index
        elif start is not None and index > start and line.startswith("Write-Host 'Step "):
            end = index
            break
    assert start is not None, "the script has no step " + str(number)
    return "\n".join(lines[start:end])


def _pwsh() -> str:
    """The PowerShell of the machine of the tests.

    A missing PowerShell is a failure and not a skip: the gate of the
    task is that the pwsh tests run, and a skip would hide the gate.
    """
    if not PWSH.is_file():
        pytest.fail("the gate of AD 1.5 task 4 requires the pwsh tests to run")
    return str(PWSH)


def _run_pwsh(program: str) -> str:
    """Run a program under pwsh and return its output."""
    result = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def _header_of(script: str) -> str:
    """The header of the script: the part before the first step."""
    marker = "Write-Host 'Step 1:"
    assert marker in script, "the script has no step 1"
    return script.split(marker)[0]


def _read_back_header(script: str, tmp_path: Path) -> list[str]:
    """The three values of the header, read back under pwsh.

    The values are written as base64 of their UTF-8 bytes, so a value
    that holds a newline or a quote comes back byte for byte.
    """
    program = (
        _header_of(script)
        + "\n$values = @($Device, $HostName, $Domain) | ForEach-Object {\n"
        + "    [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($_))\n"
        + "}\n"
        + "$values -join ','\n"
    )
    path = tmp_path / "header.ps1"
    path.write_text(program, encoding="utf-8")
    result = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return [
        base64.b64decode(part).decode("utf-8")
        for part in result.stdout.strip().split(",")
    ]


def _parse_errors(script: str) -> list[str]:
    """The parse errors of a script, under the parser of pwsh."""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    program = (
        "$errors = $null\n"
        "$tokens = $null\n"
        f"$text = [System.Text.Encoding]::UTF8.GetString("
        f"[System.Convert]::FromBase64String('{encoded}'))\n"
        "[void][System.Management.Automation.Language.Parser]::ParseInput("
        "$text, [ref]$tokens, [ref]$errors)\n"
        "foreach ($error in $errors) { $error.ToString() }\n"
    )
    return [line for line in _run_pwsh(program).splitlines() if line.strip()]


def _command_names(script: str) -> list[str]:
    """The names of the commands of a script, under the parser of pwsh."""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    program = (
        "$errors = $null\n"
        "$tokens = $null\n"
        f"$text = [System.Text.Encoding]::UTF8.GetString("
        f"[System.Convert]::FromBase64String('{encoded}'))\n"
        "$ast = [System.Management.Automation.Language.Parser]::ParseInput("
        "$text, [ref]$tokens, [ref]$errors)\n"
        "$ast.FindAll({param($node) $node -is "
        "[System.Management.Automation.Language.CommandAst]}, $true) | "
        "ForEach-Object { $_.GetCommandName() }\n"
    )
    return [line for line in _run_pwsh(program).splitlines() if line.strip()]


def _write_config(tmp_path: Path, text: str) -> Path:
    """The sshd configuration of the test."""
    path = tmp_path / "sshd_config"
    path.write_text(text, encoding="utf-8")
    return path


def _run_config_step(script: str, tmp_path: Path, config: Path) -> str:
    """Run the step of the configuration under pwsh and return the file.

    The backup is made once, from the configuration as it is before the
    first run, as step 2 of the script makes it.
    """
    backup = Path(str(config) + ".bak")
    if not backup.exists():
        backup.write_bytes(config.read_bytes())
    program = (
        "$SshdConfig = '" + str(config).replace("'", "''") + "'\n"
        "$SshdBackup = '" + str(config) + ".bak'\n"
        + _step(script, 7)
    )
    path = tmp_path / "step7.ps1"
    path.write_text(program, encoding="utf-8")
    result = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return config.read_text(encoding="utf-8")


def test_the_block_is_written_ahead_of_the_administrators_block(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    script = _render(golden_plan)
    config = _write_config(tmp_path, FAKE_SSHD_CONFIG)
    written = _run_config_step(script, tmp_path, config)
    lines = written.split("\n")
    build = lines.index("Match User newton-build,adbuild\\newton-build")
    administrators = lines.index("Match Group administrators")
    assert build < administrators
    assert "# newton-ad build" in lines
    assert lines[build - 1] == "# newton-ad build"


def test_the_password_authentication_is_off_where_it_is_global(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    script = _render(golden_plan)
    config = _write_config(tmp_path, FAKE_SSHD_CONFIG)
    written = _run_config_step(script, tmp_path, config)
    lines = [line for line in written.split("\n") if line.strip()]
    first_match = next(
        index for index, line in enumerate(lines) if line.startswith("Match ")
    )
    assert "PasswordAuthentication no" in lines[:first_match]
    assert "KbdInteractiveAuthentication no" in lines[:first_match]
    assert "PasswordAuthentication yes" not in written
    assert "KbdInteractiveAuthentication yes" not in written


def test_the_settings_are_added_when_the_configuration_has_none(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    script = _render(golden_plan)
    config = _write_config(tmp_path, "Port 22\n")
    written = _run_config_step(script, tmp_path, config)
    assert "PasswordAuthentication no" in written
    assert "KbdInteractiveAuthentication no" in written
    assert "Match User newton-build,adbuild\\newton-build" in written


def test_a_second_run_writes_one_block(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    script = _render(golden_plan)
    config = _write_config(tmp_path, FAKE_SSHD_CONFIG)
    _run_config_step(script, tmp_path, config)
    written = _run_config_step(script, tmp_path, config)
    assert written.count("Match User newton-build,adbuild\\newton-build") == 1
    assert written.count("# newton-ad build") == 1


def test_a_run_for_another_netbios_replaces_the_match_line(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    config = _write_config(tmp_path, FAKE_SSHD_CONFIG)
    _run_config_step(_render(golden_plan), tmp_path, config)
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["netbios"] = "OTHERNB"
    written = _run_config_step(_render(plan.plan_build(inputs)), tmp_path, config)
    assert "Match User newton-build,othernb\\newton-build" in written
    assert "adbuild\\newton-build" not in written
    assert written.count("# newton-ad build") == 1


def test_three_runs_write_the_same_bytes(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    script = _render(golden_plan)
    config = _write_config(tmp_path, FAKE_SSHD_CONFIG)
    outputs = [config.read_bytes()]
    for _ in range(3):
        _run_config_step(script, tmp_path, config)
        outputs.append(config.read_bytes())
    assert outputs[1] == outputs[2] == outputs[3]


def test_the_block_is_written_when_there_is_no_administrators_block(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    script = _render(golden_plan)
    config = _write_config(tmp_path, "Port 22\nMatch Group other\n   X y\n")
    written = _run_config_step(script, tmp_path, config)
    lines = [line for line in written.split("\n") if line.strip()]
    first_match = next(
        index for index, line in enumerate(lines) if line.startswith("Match ")
    )
    # The two settings are global: they are ahead of the first block.
    assert "PasswordAuthentication no" in lines[:first_match]
    assert "KbdInteractiveAuthentication no" in lines[:first_match]
    assert "Match User newton-build,adbuild\\newton-build" in written


# --------------------------------------------------------------------------
# The order of the steps
# --------------------------------------------------------------------------


def test_sshd_is_started_once_before_the_configuration_is_read(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert script.count("Start-Service -Name 'sshd'") == 1
    started = script.index("Start-Service -Name 'sshd'")
    read = script.index("Get-Content -LiteralPath $SshdBackup")
    assert started < read


def test_sshd_starts_with_the_server(helper: Path, golden_plan: dict[str, Any]) -> None:
    script = _render(golden_plan)
    step = _step(script, 2)
    assert "Set-Service -Name 'sshd' -StartupType Automatic" in step
    # The startup type is set before the service is started, and the
    # service is started only when it is not running yet.
    assert step.index("Set-Service -Name 'sshd' -StartupType Automatic") < step.index(
        "Start-Service -Name 'sshd'"
    )


def test_the_configuration_is_backed_up(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert (
        "Copy-Item -LiteralPath $SshdConfig -Destination $SshdBackup -Force"
        in script
    )
    assert "$SshdBackup = 'C:\\ProgramData\\ssh\\sshd_config.bak-newton-build'" in script


def test_the_sshd_is_restarted_at_the_end(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert script.rindex("Register-ScheduledTask") > script.index(
        "Set-NetFirewallRule"
    )


def test_the_sshd_restart_goes_through_a_system_task(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    step = _step(script, 10)
    assert "Unregister-ScheduledTask -TaskName $RestartTask" in step
    assert "New-ScheduledTaskAction -Execute 'powershell.exe'" in step
    assert "New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(8)" in step
    assert "New-ScheduledTaskPrincipal -UserId 'SYSTEM'" in step
    assert "Register-ScheduledTask -TaskName $RestartTask" in step
    assert "Restart-Service sshd -Force" in step
    # The restart is the argument of the task and not a call of the
    # script: the session of the owner ends when sshd restarts.
    assert "Restart-Service -Name 'sshd' -Force" not in script
    assert "$RestartTask = 'Newton AD build sshd restart'" in script


def test_the_sshd_restart_does_not_depend_on_a_changed_configuration(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    # Open point 76 (the maintainer, 2026-11-21): a re-run after a stop past the
    # configuration step finds the block in place, and sshd must still be
    # restarted to pick the configuration up.
    step = _step(_render(golden_plan), 10)
    assert "$sshdChanged" not in step
    assert "Register-ScheduledTask -TaskName $RestartTask" in step
    assert "did not change. Nothing is restarted" not in step


def test_the_owner_is_told_to_run_the_bootstrap_at_a_console_or_over_ssh_tt(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    # Open point 75 (the maintainer, 2026-11-21): Read-Host -AsSecureString hangs when
    # stdin is a pipe; the owner runs the script at the server's console or
    # in an interactive ssh session.  The header and the line before the
    # first prompt both say so.
    script = _render(golden_plan)
    wording = "at the server's console or in an interactive ssh session (ssh -tt)"
    header = script[: script.index("param(")]
    assert wording in header
    prompt = script.index("Read-Host -AsSecureString")
    assert wording in script[script.rindex("Write-Host", 0, prompt) : prompt]


def test_the_bootstrap_names_the_dns_prep_before_stage_0(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    # Open point 79 (the maintainer, 2026-11-21).
    script = _render(golden_plan)
    wording = "set the server's DNS client to a resolver that answers before stage 0"
    assert wording in script[script.rindex("Write-Host ''") :]


def test_the_restart_task_removes_itself(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    # A finished build leaves no SYSTEM task behind: the task that
    # restarts sshd unregisters itself in the same command.
    step = _step(_render(golden_plan), 10)
    action = next(
        line for line in step.split("\n") if "New-ScheduledTaskAction" in line
    )
    argument = action.split("-Argument", 1)[1]
    assert "Restart-Service sshd -Force" in argument
    assert "Unregister-ScheduledTask" in argument
    assert "Newton AD build sshd restart" in argument
    assert "removed by the next run" not in step


# --------------------------------------------------------------------------
# The firewall rule and the Proxmox variant
# --------------------------------------------------------------------------


def test_the_firewall_rule_holds_the_profile_any(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert "Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Profile Any" in script
    assert "-Profile Any | Out-Null" in script


def test_the_proxmox_variant_installs_the_driver_and_the_agent(
    helper: Path, proxmox_plan: dict[str, Any]
) -> None:
    script = _render(proxmox_plan)
    assert "vioserial\\2k25\\amd64\\vioser.inf" in script
    assert "guest-agent\\qemu-ga-x86_64.msi" in script
    assert "pnputil.exe /add-driver" in script
    assert "Start-Process -FilePath 'msiexec.exe'" in script
    assert "QEMU-GA" in script


def test_the_agent_install_waits_for_msiexec(
    helper: Path, proxmox_plan: dict[str, Any]
) -> None:
    script = _render(proxmox_plan)
    step = _step(script, 10)
    assert "Start-Process -FilePath 'msiexec.exe'" in step
    assert "-Wait -PassThru" in step
    assert ".ExitCode" in step
    assert "& msiexec.exe" not in step


def test_a_driver_already_up_to_date_passes_only_when_the_device_is_ok(
    helper: Path, proxmox_plan: dict[str, Any]
) -> None:
    # Measured on BUILD1, 2026-11-18: on a server whose VirtIO serial
    # driver is installed already, `pnputil /add-driver ... /install`
    # prints "Driver package is up-to-date on device" and exits 259
    # (ERROR_NO_MORE_ITEMS), and the bootstrap stopped at step 10.  259
    # passes only when the VirtIO Serial device then reads Status OK.
    step = _step(_render(proxmox_plan), 10)
    assert "($LASTEXITCODE -ne 259)" in step
    assert (
        "if ($LASTEXITCODE -eq 259) {\n"
        "    $serial = @(Get-PnpDevice -PresentOnly -FriendlyName 'VirtIO Serial Driver' -ErrorAction SilentlyContinue)\n"
        "    if (($serial.Count -lt 1) -or (@($serial | Where-Object { $_.Status -ne 'OK' }).Count -gt 0)) {\n"
        "        throw 'the VirtIO serial driver was not installed'\n"
        "    }\n"
        "}\n"
    ) in step


def test_the_virtio_media_is_looked_for_on_the_cd_rom_drives_only(
    helper: Path, proxmox_plan: dict[str, Any]
) -> None:
    # A user who is not an administrator may create a folder in C:\,
    # so the media is looked for on the CD-ROM volumes and nowhere else.
    step = _step(_render(proxmox_plan), 10)
    assert "DriveType=5" in step
    assert "Get-PSDrive" not in step


def test_the_other_variant_installs_no_driver(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert "vioserial" not in script
    assert "qemu-ga" not in script


# --------------------------------------------------------------------------
# The account, the key and the password
# --------------------------------------------------------------------------


def test_the_key_and_the_password_file_are_protected(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert "'S-1-5-32-544'" in script
    assert "'S-1-5-18'" in script
    for path in ("$PasswordFile", "$KeyFile", "$HelperFile", "$KeysFile"):
        assert f"Protect-NewtonPath -Path {path} -Inheritance 'None'" in script
    assert "SetAccessRuleProtection($true, $false)" in script


def test_the_build_directory_is_protected_before_the_password_is_written(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    protected = script.index(
        "Protect-NewtonPath -Path $BuildDir -Inheritance 'ContainerInherit, ObjectInherit'"
    )
    written = script.index("[System.IO.File]::WriteAllBytes($PasswordFile, $protected)")
    assert protected < written


def test_the_password_is_never_shown(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    for line in script.split("\n"):
        if "Write-Host" in line:
            assert "$password" not in line
            assert "$secure" not in line
            assert "$plain" not in line
    assert "Write-Host 'The build account is created with a random password." in script


def test_the_password_is_in_the_dpapi_file_of_the_machine(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert "$PasswordFile = 'C:\\NewtonBuild\\pw.bin'" in script
    assert "[System.Security.Cryptography.DataProtectionScope]::LocalMachine" in script
    assert (
        "[System.IO.File]::WriteAllBytes($PasswordFile, $protected)" in script
    )


def test_the_dpapi_assembly_is_loaded_before_the_password_is_protected(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    # Measured on BUILD1, 2026-11-18 (MEASURED-1.5 "Stage 8 on BUILD1,
    # 2026-11-18"): Windows PowerShell 5.1 does not load System.Security
    # by itself, and the bootstrap stopped at step 3 with "Unable to find
    # type [System.Security.Cryptography.ProtectedData]".
    script = _render(golden_plan)
    load = script.find("Add-Type -AssemblyName System.Security\n")
    assert load != -1
    assert load < script.index("[System.Security.Cryptography.ProtectedData]::Protect(")


def test_the_password_file_holds_the_bytes_the_helper_decodes(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    # Measured on BUILD1, 2026-11-18: the bootstrap wrote the password as
    # UTF-16LE, the helper read it as UTF-8, and stage 2's password task
    # failed "The user name or password is incorrect." Both sides use
    # UTF-8 (the bytes of the measured stand-in, MEASURED-1.5 "Set-up").
    script = _render(golden_plan)
    assert "$plain = [System.Text.Encoding]::UTF8.GetBytes($password)" in script
    assert "Unicode.GetBytes($password)" not in script
    source = (Path(bootstrap.__file__).with_name("helper") / "build.ps1").read_text(encoding="utf-8")
    decode = source[source.index("function Get-NewtonBuildPassword"):]
    decode = decode[: decode.index("\nfunction ", 1)]
    assert "return [Text.Encoding]::UTF8.GetString(" in decode


def test_the_key_of_the_server_is_written_into_the_install_root_of_the_helper(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert "$KeyFile = 'C:\\ProgramData\\Newton\\ad-build\\key.hex'" in script
    # The key is derived on the server and written there: the script
    # holds the derivation and not the key.
    assert "$keyHex = Get-ApprovalKeyHex $passphrase $Device" in script
    assert (
        "[System.IO.File]::WriteAllText($KeyFile, $keyHex, "
        "(New-Object System.Text.UTF8Encoding($false)))" in script
    )


def _without_the_helper_blob(script: str) -> str:
    """The script without the base64 of the helper."""
    match = re.search(r"\$helperB64 = @\(\n(.*?)\n\)", script, re.DOTALL)
    if match is None:
        return script
    return script[: match.start(1)] + script[match.end(1) :]


def test_the_script_holds_no_key(helper: Path, golden_plan: dict[str, Any]) -> None:
    script = _render(golden_plan)
    # The key of the server mints every token and derives every secret
    # of the build: whoever renders the script must not hold it.
    key = approve.derive_k(b"pass", "build1")
    assert key not in script
    assert re.findall(r"[0-9a-f]{64}", _without_the_helper_blob(script)) == []


def _function_of(script: str, name: str) -> str:
    """The text of one function of the script."""
    lines = script.split("\n")
    start = next(
        index
        for index, line in enumerate(lines)
        if line.startswith(f"function {name}(")
    )
    end = start
    while lines[end].rstrip() != "}":
        end += 1
    return "\n".join(lines[start : end + 1])


def test_the_server_derives_the_key_the_host_derives(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    program = (
        _function_of(script, "Get-ApprovalKeyHex")
        + "\nGet-ApprovalKeyHex 'pass' 'build1'\n"
    )
    assert _run_pwsh(program).strip() == approve.derive_k(b"pass", "build1")


def test_the_server_prints_the_fingerprint_the_host_prints(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    # The owner compares the fingerprint the server prints with the one
    # the Newton host prints: the two must come from the same rule.
    script = _render(golden_plan)
    function = _function_of(script, "Get-ApprovalFingerprintHex")
    for passphrase, device in ((b"pass", "build1"), (b"other passphrase", "build2")):
        key = approve.derive_k(passphrase, device)
        program = function + f"\nGet-ApprovalFingerprintHex '{key}'\n"
        assert _run_pwsh(program).strip() == approve.approval_fingerprint(key)


def test_the_helper_of_the_package_is_installed(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    match = re.search(
        r"\$helperB64 = @\(\n(.*?)\n\)\n\$helperB64 = \$helperB64 -join ''",
        script,
        re.DOTALL,
    )
    assert match is not None
    encoded = "".join(
        line.strip().strip("'")
        for line in match.group(1).split("\n")
        if line.strip()
    )
    assert base64.b64decode(encoded) == HELPER_BYTES
    assert (
        "[System.IO.File]::WriteAllBytes($HelperFile, "
        "[System.Convert]::FromBase64String($helperB64))" in script
    )


def test_the_keys_file_is_created_and_the_public_key_is_written(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    script = _render(golden_plan)
    assert "$KeysFile = 'C:\\NewtonBuild\\authorized_keys'" in script
    assert "[string]$PublicKey" in script
    assert "$keyLine -cmatch '^(ssh-(?:ed25519|rsa)) " in script
    # The key of the build is restricted: it may not open a tunnel, a
    # terminal or a forwarding, whatever the block of the account says.
    assert "'restrict ' + $keyType + ' ' + $keyBody" in script


def _run_keys_step(
    script: str, tmp_path: Path, keys: Path, public_key: str
) -> subprocess.CompletedProcess[str]:
    """Run the step of the keys file under pwsh."""
    program = (
        "$ErrorActionPreference = 'Stop'\n"
        "$KeysFile = '" + str(keys).replace("'", "''") + "'\n"
        "$PublicKey = '" + public_key.replace("'", "''") + "'\n"
        + _step(script, 4)
    )
    path = tmp_path / "step4.ps1"
    path.write_text(program, encoding="utf-8")
    return subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def test_a_planted_key_is_removed_when_no_public_key_is_given(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    keys = tmp_path / "authorized_keys"
    keys.write_bytes(b"ssh-ed25519 AAAAPLANTED attacker\n")
    result = _run_keys_step(_render(golden_plan), tmp_path, keys, "")
    assert result.returncode == 0, result.stdout + result.stderr
    assert keys.read_bytes() == b""


#: A synthetic ed25519 key body: the length-prefixed type and 32 bytes.
ED25519_BODY = base64.b64encode(
    b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + bytes(range(32))
).decode("ascii")


def test_the_comment_of_a_public_key_line_is_dropped(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    keys = tmp_path / "authorized_keys"
    line = "ssh-ed25519 " + ED25519_BODY + " owner@build-host"
    result = _run_keys_step(_render(golden_plan), tmp_path, keys, line)
    assert result.returncode == 0, result.stdout + result.stderr
    assert keys.read_bytes() == (
        "restrict ssh-ed25519 " + ED25519_BODY + "\n"
    ).encode("ascii")


def test_a_key_whose_body_carries_another_type_is_refused(
    helper: Path, golden_plan: dict[str, Any], tmp_path: Path
) -> None:
    keys = tmp_path / "authorized_keys"
    result = _run_keys_step(
        _render(golden_plan), tmp_path, keys, "ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQAB"
    )
    assert result.returncode != 0
    assert not keys.exists() or b"AAAAB3NzaC1yc2E" not in keys.read_bytes()


# --------------------------------------------------------------------------
# The values that reach the script
# --------------------------------------------------------------------------


def _single_quoted_spans(text: str) -> list[tuple[int, int]]:
    """The spans of the single-quoted strings of a PowerShell source."""
    spans: list[tuple[int, int]] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "#":
            newline = text.find("\n", index)
            index = length if newline < 0 else newline
            continue
        if char == "'":
            start = index
            index += 1
            while index < length:
                if text[index] == "'":
                    if index + 1 < length and text[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            spans.append((start, index))
            continue
        if char == '"':
            index += 1
            while index < length:
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            continue
        index += 1
    return spans


def _every_occurrence_is_in_a_literal(
    text: str, needle: str, spans: list[tuple[int, int]]
) -> bool:
    """Whether every occurrence of a value is inside a single-quoted string."""
    start = 0
    while True:
        at = text.find(needle, start)
        if at < 0:
            return True
        if not any(
            begin <= at and at + len(needle) <= end for begin, end in spans
        ):
            return False
        start = at + 1


@pytest.mark.parametrize("hostile", HOSTILE_VALUES)
def test_a_hostile_value_stays_inside_its_literal(
    helper: Path, golden_plan: dict[str, Any], hostile: str, tmp_path: Path
) -> None:
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    # The NetBIOS name is a name of the plan and not a free value: the
    # case of a hostile NetBIOS name is its own test.
    inputs["domain"]["netbios"] = "ADBUILD"
    inputs["domain"]["dns_name"] = hostile
    inputs["servers"][0]["device"] = hostile
    inputs["servers"][0]["hostname"] = hostile
    the_plan = {
        "domain": dict(inputs["domain"]),
        "servers": [dict(inputs["servers"][0])],
        "baseline": dict(inputs["baseline"]),
        "accepted_findings": [dict(one) for one in inputs["accepted_findings"]],
    }
    script = bootstrap.render_bootstrap(the_plan, "dc1")

    # The value is in the script in its escaped form: each of the four
    # single-quote characters is doubled and nothing else is touched.
    escaped = (
        "'"
        + re.sub("['\u2018\u2019\u201a\u201b]", lambda m: m.group(0) * 2, hostile)
        + "'"
    )
    assert f"$Device = {escaped}" in script
    assert f"$HostName = {escaped}" in script
    assert f"$Domain = {escaped}" in script

    # The value is in the script, and every one of its occurrences is
    # inside a single-quoted string.
    for value in {hostile, hostile.lower()}:
        if value not in script:
            continue
        spans = _single_quoted_spans(script)
        assert _every_occurrence_is_in_a_literal(script, value, spans), value

    # The script is a valid PowerShell script, and it holds the same
    # commands as the golden one: a value that broke out of its string
    # would add a command.
    assert _parse_errors(script) == []
    assert _command_names(script) == _command_names(_render(golden_plan))

    # The script reads the hostile value back byte for byte: the value
    # that reaches the script is the value that was given to it.
    assert _read_back_header(script, tmp_path) == [hostile, hostile, hostile]


def test_the_script_is_valid_powershell(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    assert _parse_errors(_render(golden_plan)) == []


def test_a_value_that_holds_a_placeholder_is_not_filled_in(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0]["device"] = "@@BUILD_DIR@@"
    the_plan = {
        "domain": dict(inputs["domain"]),
        "servers": [dict(inputs["servers"][0])],
        "baseline": dict(inputs["baseline"]),
        "accepted_findings": [dict(one) for one in inputs["accepted_findings"]],
    }
    script = bootstrap.render_bootstrap(the_plan, "dc1")
    assert "$Device = '@@BUILD_DIR@@'" in script


# --------------------------------------------------------------------------
# The refusals
# --------------------------------------------------------------------------


def test_the_render_is_refused_without_the_helper(
    golden_plan: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrap, "HELPER_PATH", tmp_path / "there-is-no-helper.ps1")
    with pytest.raises(bootstrap.BootstrapRefused) as caught:
        _render(golden_plan)
    assert caught.value.code == "no_helper"


def test_the_render_is_refused_when_the_plan_holds_no_server(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    with pytest.raises(bootstrap.BootstrapRefused) as caught:
        bootstrap.render_bootstrap(golden_plan, "dc3")
    assert caught.value.code == "schema"


def test_the_render_is_refused_when_the_plan_is_not_an_object(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    with pytest.raises(bootstrap.BootstrapRefused) as caught:
        bootstrap.render_bootstrap("not a plan", "dc1")
    assert caught.value.code == "schema"


@pytest.mark.parametrize(
    "hostile",
    ["x,*,y", "a b", "x\nPermitRootLogin yes", "*"],
)
def test_a_netbios_that_is_sshd_syntax_is_refused(
    helper: Path, golden_plan: dict[str, Any], hostile: str
) -> None:
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["netbios"] = hostile
    the_plan = {
        "domain": dict(inputs["domain"]),
        "servers": [dict(inputs["servers"][0])],
        "baseline": dict(inputs["baseline"]),
        "accepted_findings": [dict(one) for one in inputs["accepted_findings"]],
    }
    with pytest.raises(bootstrap.BootstrapRefused) as caught:
        bootstrap.render_bootstrap(the_plan, "dc1")
    assert caught.value.code == "schema"


def test_a_server_outside_the_plan_is_refused(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    outside = dict(golden_plan["servers"][0])
    outside["device"] = "build2"
    with pytest.raises(bootstrap.BootstrapRefused) as caught:
        bootstrap.render_bootstrap(golden_plan, outside)
    assert caught.value.code == "schema"


def test_an_unknown_checkpoint_is_refused(
    helper: Path, golden_plan: dict[str, Any]
) -> None:
    the_plan = copy.deepcopy(golden_plan)
    the_plan["servers"][0]["checkpoint"] = "bogus"
    with pytest.raises(bootstrap.BootstrapRefused) as caught:
        bootstrap.render_bootstrap(the_plan, "dc1")
    assert caught.value.code == "schema"


# --------------------------------------------------------------------------
# the stage 8 templates (the maintainer's decision on DESIGN-1.5 open point 34,
# 2026-11-16): DC1's bootstrap installs the generators' build templates
# --------------------------------------------------------------------------


def _blob(script: str, name: str) -> bytes:
    match = re.search(r"^\$" + name + r" = @\(\n((?:'[A-Za-z0-9+/=]+'\n)+)\)$", script, re.MULTILINE)
    assert match, name
    return base64.b64decode("".join(line.strip("'") for line in match.group(1).split()))


def test_the_stage_8_templates_are_the_generators_build_templates(golden_plan: dict[str, Any], tmp_path: Path,
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    from newton_mcp.ad import setupgen, setupgen_write

    path = tmp_path / "build.ps1"
    path.write_bytes(HELPER_BYTES)
    monkeypatch.setattr(bootstrap, "HELPER_PATH", path)
    script = _render(golden_plan)
    assert _blob(script, "s8AuditB64") == setupgen.windows_template(build=True).encode("utf-8")
    assert _blob(script, "s8OpsB64") == setupgen_write.windows_write_template(build=True).encode("utf-8")
    assert "(Join-Path $InstallRoot 's8-audit.tmpl.ps1')" in script
    assert "(Join-Path $InstallRoot 's8-ops.tmpl.ps1')" in script
    from newton_mcp.ad import setupgen_write

    assert _blob(script, "s8WriteB64") == setupgen_write.WRITE_HELPER_PATH.read_bytes()
    # the owner reads where the write helper went and what stage 8 does with it
    assert "Write-Host ('The write helper of stage 8 is in ' + $WriteHelperFile" in script


def test_dc2s_bootstrap_installs_no_stage_8_template(helper: Path) -> None:
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"].append(dict(inputs["servers"][0], device="build2", role="dc2", hostname="DC2", ip="192.0.2.12"))
    two = plan.plan_build(inputs)
    assert "s8AuditB64" in _render(two, "dc1")
    script = _render(two, "dc2")
    assert "s8AuditB64" not in script and "s8OpsB64" not in script
    assert "tmpl.ps1" not in script
