"""The bootstrap of one build server (DESIGN-1.5 "The bootstrap").

The bootstrap is the one step Newton asks of the owner: Newton renders
one script per server, the owner runs it on the fresh server as an
Administrator, and every stage of the build runs over SSH after that.
The script is printed and never run by Newton.

WHAT THE SCRIPT DOES

It installs OpenSSH if it is not installed yet, starts sshd once so
that its configuration file exists, and backs the configuration up.
It creates the local build account ``newton-build`` with a random
password that is never shown and never stored in clear: the password
is in a DPAPI file of the machine, and only SYSTEM and the
Administrators may read that file.  It writes the keys file of the
account and the build helper, and it protects them and the file of the
password with the same rule.  It writes the block of the account into
the sshd configuration, ahead of the block of the administrators, with
the forced command of the helper, and it turns the password
authentication off everywhere, so that a login in the UPN form cannot
fall through to a password shell.  It gives the SSH firewall rule the
profile Any, because the rule of a fresh server holds the profile of
the network it is on, and the network of a build is a lab network that
is often a public one.  On a Proxmox guest it installs the VirtIO
serial driver and the QEMU guest agent, because the guest agent needs
the driver of the serial device.

THE KEY K OF THE SERVER

The key K of the server is not in the script and is not an argument of
the render: whoever renders the script would hold it, and K mints
every token of the build and derives the DSRM and the admin passwords.
The script asks the owner for the passphrase of the build twice, on
the server (Read-Host needs a console, so the owner runs the script at
the server's console or in an interactive ssh session, ``ssh -tt``; open
point 75, ruled 2026-11-21), and derives K there with the derivation of the approve
module -- the function ``Get-ApprovalKeyHex`` of the 1.4 setup, copied
as it is.  The server writes K in the helper's install root, where only
SYSTEM and the Administrators may read it, and prints the fingerprint
of the key and not the key.  Whoever renders the script never holds K,
so a Newton machine that is compromised cannot mint a token of the
build without the owner's passphrase; the Newton host derives K itself
whenever newton-approve runs with that passphrase.

THE PUBLIC KEY

The plan holds no key and the render takes none, so the script takes
the public key of the build as its one parameter and writes it in the
keys file of the account.  The keys file is written on every run:
without that parameter it is emptied, and the owner has to put the key
in it before the first login.

THE ORDER OF THE CONFIGURATION

The block of the build account is written ahead of the block of the
administrators.  Every Match block that matches applies, and for each
keyword the first value sshd reads wins; the build account is an
administrator, so the administrators block matches it too, and the
AuthorizedKeysFile of the account must come before the one of that
block, or the keys file of the administrators would win.  The two
global settings are written before the first Match
block, because a setting behind a Match block is the setting of that
block and not a global one.

THE VALUES THAT REACH THE SCRIPT

The values of the plan reach the script as the contents of
single-quoted PowerShell strings, and the only characters that are
escaped are the four single-quote characters (the ASCII quote and
U+2018, U+2019, U+201A and U+201B, each of which ends a single-quoted
string in PowerShell): inside a single-quoted string a backtick, a
dollar sign, a semicolon and a newline are characters and not syntax.  The NetBIOS name is the one value that is checked
against the grammar of the plan, because it reaches the configuration
of sshd as the name of a user; the other values are not checked here,
so a value that came from anywhere else cannot break out of its
string.

THE HELPER

The script installs the build helper of the package, and the path of
that helper is the one of the file map of PLAN-1.5.  The helper is
written by task 3; until it is in the build, the render is refused
with the code ``no_helper`` rather than a script that installs
nothing.

THE WRITE HELPER OF STAGE 8

DC1's script also installs the 1.4 write helper that stage 8 sets up
for newton-ops, at a fixed path in the install root
(``WRITE_HELPER_FILE``), where only SYSTEM and the Administrators may
write it.  No request of the build carries it: Windows PowerShell 5.1
under the server's OpenSSH hangs reading stdin past about 70 to 80 KB
(measured on BUILD1, 2026-11-18), and the write helper is about 182 KB
in a request (the maintainer's decision of 2026-11-19 on the stage 8 transport).
The script prints the sha256 of the file it wrote, for the owner to
compare with the write helper sha256 that ``newton-approve`` prints for
the plan, and at stage 8 the helper checks the file against the plan's
``ops.write_helper_sha256`` before anything runs: a file that is
missing or changed stops the stage, and the next step is to run this
script again.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..setupgen import _b64_literal as _b64_literal
from .plan import CHECKPOINT_METHODS, NETBIOS_RE


#: The helper the bootstrap installs on the server.  The path is the
#: one of the file map of PLAN-1.5.
HELPER_PATH = Path(__file__).with_name("helper") / "build.ps1"

#: The directory of the build on the server.  The design names it for
#: the file of the password.
BUILD_DIR = r"C:\NewtonBuild"

#: The file of the password of the build account: the DPAPI blob of
#: the machine, and not the password.
PASSWORD_FILE = BUILD_DIR + r"\pw.bin"

#: The install root of the helper: where ``build.ps1`` reads K, the
#: device name and its journal (its ``DefaultInstallRoot``; the root the
#: lab measured with; DESIGN-1.5 open point 23 of task 8).
INSTALL_ROOT = r"C:\ProgramData\Newton\ad-build"

#: The file of the key K of the server (the helper's ``KeyFileName``).
KEY_FILE = INSTALL_ROOT + r"\key.hex"

#: The file of the device name of the server (the helper's
#: ``DeviceFileName``): the helper finds itself in the plan by it.
DEVICE_FILE = INSTALL_ROOT + r"\device.txt"

#: The file of the build helper, in its install root.
HELPER_FILE = INSTALL_ROOT + r"\build.ps1"

#: The file of the 1.4 write helper of stage 8 on DC1, in the install root
#: (the helper's ``WriteHelperFileName``; the maintainer's decision of 2026-11-19).
WRITE_HELPER_FILE = INSTALL_ROOT + r"\s8-write.ps1"

#: The keys file of the build account: the file sshd reads the public
#: key of the account from.
KEYS_FILE = BUILD_DIR + r"\authorized_keys"

#: The sshd configuration of the server.
SSHD_CONFIG = r"C:\ProgramData\ssh\sshd_config"

#: The backup of the sshd configuration.  The cleanup of stage 9 puts
#: the backed-up configuration back.
SSHD_BACKUP = r"C:\ProgramData\ssh\sshd_config.bak-newton-build"

#: The name of the build account.
BUILD_USER = "newton-build"

#: The marker of the block of the build account.
BLOCK_MARKER = "# newton-ad build"

#: The name of the scheduled task that restarts sshd at the end of the
#: bootstrap: it runs as SYSTEM, so that the restart does not depend on
#: the session of the owner, and it unregisters itself after the
#: restart, so that a finished build leaves no task behind.
RESTART_TASK = "Newton AD build sshd restart"

#: The codes the bootstrap refuses with.
REFUSAL_CODES: tuple[str, ...] = ("schema", "no_helper")


class BootstrapRefused(Exception):
    """The bootstrap is refused with one of the codes of the bootstrap.

    The code is the word the caller answers with; the message is for
    the log and never carries the value that was refused.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


def _refuse(code: str, message: str) -> BootstrapRefused:
    return BootstrapRefused(code, message)


# --------------------------------------------------------------------------
# The values that reach the script
# --------------------------------------------------------------------------


#: The four single-quote characters of PowerShell.
_QUOTES_RE = re.compile("['\u2018\u2019\u201a\u201b]")


def _escape(value: Any, where: str) -> str:
    """The contents of a PowerShell single-quoted string.

    Each of the four single-quote characters (the ASCII quote and
    U+2018, U+2019, U+201A and U+201B: PowerShell ends a single-quoted
    string at any of them) is doubled, and nothing else is touched:
    inside a single-quoted string a backtick, a dollar sign, a
    semicolon and a newline are characters and not syntax, so a value
    that came from anywhere else stays inside its string.
    """
    if not isinstance(value, str):
        raise _refuse("schema", f"{where} is not text")
    if "\x00" in value:
        raise _refuse("schema", f"{where} holds a NUL")
    return _QUOTES_RE.sub(lambda match: match.group(0) * 2, value)


def _literal(value: Any, where: str) -> str:
    """A PowerShell single-quoted string that holds a value."""
    return "'" + _escape(value, where) + "'"


def _text(value: Any, where: str) -> str:
    """A value that must be text."""
    if not isinstance(value, str):
        raise _refuse("schema", f"{where} is not text")
    return value


#: The placeholder of a value of the script.
_PLACEHOLDER_RE = re.compile(r"@@[A-Z_]+@@")


def _fill(template: str, values: Mapping[str, str]) -> str:
    """The template with its placeholders filled in.

    The placeholders are filled in one pass, so a value that holds the
    text of a placeholder is never filled in again.
    """
    return _PLACEHOLDER_RE.sub(
        lambda match: values.get(match.group(0), match.group(0)), template
    )


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    """A value that must be an object."""
    if not isinstance(value, Mapping):
        raise _refuse("schema", f"{where} is not an object")
    return value


def _server_of(plan: Mapping[str, Any], server: Any) -> Mapping[str, Any]:
    """The server the bootstrap is rendered for.

    The server is the role (``dc1`` or ``dc2``) or the server itself.
    """
    servers = plan.get("servers")
    if not isinstance(servers, Sequence) or isinstance(servers, (str, bytes)):
        raise _refuse("schema", "the plan holds no servers")
    if isinstance(server, str):
        for one in servers:
            if isinstance(one, Mapping) and one.get("role") == server:
                return one
        raise _refuse("schema", "the plan holds no server of that role")
    if isinstance(server, Mapping):
        # The server is one of the servers of the plan: a server that
        # is not in the plan is not a server of that plan.
        if not any(server == one for one in servers):
            raise _refuse("schema", "the server is not one of the plan")
        return server
    raise _refuse("schema", "the server is neither a role nor a server")


#: The variable names of the stage 8 templates' blobs in the script.
_STAGE8_BLOBS = {"s8-audit.tmpl.ps1": "s8AuditB64", "s8-ops.tmpl.ps1": "s8OpsB64"}


def stage8_templates() -> dict[str, bytes]:
    """The build templates of the 1.3 collector setup and the 1.4 write
    setup, by their file name in the install root.  DC1's helper fills
    them at stage 8 from the plan bytes (the maintainer's decisions on DESIGN-1.5 open
    points 34 and 37, 2026-11-16): the generators' own templates, so the
    setup the build runs is the setup an owner runs, but for the key step
    and the restart."""
    from .. import setupgen, setupgen_write

    return {
        "s8-audit.tmpl.ps1": setupgen.windows_template(build=True).encode("utf-8"),
        "s8-ops.tmpl.ps1": setupgen_write.windows_write_template(build=True).encode("utf-8"),
    }


def stage8_write_helper() -> bytes:
    """The bytes of the 1.4 write helper of the installed Newton: the file
    DC1's bootstrap installs for stage 8 (the maintainer's decision of 2026-11-19)."""
    from .. import setupgen_write

    try:
        return setupgen_write.WRITE_HELPER_PATH.read_bytes()
    except OSError:
        raise _refuse("no_helper", "the write helper is not in this build") from None


def _stage8_step(role: str) -> str:
    """The lines that install the stage 8 templates and the write helper:
    DC1's only."""
    if role != "dc1":
        return ""
    lines = [
        "# DC1's helper fills the build templates of the 1.3 and 1.4 setups at",
        "# stage 8 (the maintainer's decision on open point 34): the generators' own templates.",
    ]
    for name, data in stage8_templates().items():
        variable = _STAGE8_BLOBS[name]
        lines.append(_b64_literal(variable, data))
        lines.append(
            f"[System.IO.File]::WriteAllBytes((Join-Path $InstallRoot '{name}'), "
            f"[System.Convert]::FromBase64String(${variable}))"
        )
    lines += [
        "# The 1.4 write helper that stage 8 sets up for newton-ops. No request of the",
        "# build carries it (the maintainer's decision of 2026-11-19): Windows PowerShell 5.1 under",
        "# OpenSSH hangs reading stdin past about 70 KB, and the helper is bigger. Only",
        "# SYSTEM and the Administrators may change it; stage 8 checks it first.",
        "$WriteHelperFile = " + _literal(WRITE_HELPER_FILE, "the write helper file"),
        _b64_literal("s8WriteB64", stage8_write_helper()),
        "[System.IO.File]::WriteAllBytes($WriteHelperFile, [System.Convert]::FromBase64String($s8WriteB64))",
        "Protect-NewtonPath -Path $WriteHelperFile -Inheritance 'None'",
        "$writeHelperSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $WriteHelperFile).Hash.ToLowerInvariant()",
        "Write-Host ('The write helper of stage 8 is in ' + $WriteHelperFile + '. Only SYSTEM and the Administrators can change it.')",
        "Write-Host ('Its sha256 is ' + $writeHelperSha + '. It must be the plan''s write_helper_sha256, which newton-approve prints.')",
        "Write-Host 'Stage 8 checks it against the plan before anything runs. If it is missing or changed, stage 8 stops: run this bootstrap again.'",
    ]
    return "\n".join(lines) + "\n"


def _helper_bytes() -> bytes:
    """The bytes of the build helper of the package."""
    try:
        return HELPER_PATH.read_bytes()
    except OSError:
        raise _refuse("no_helper", "the build helper is not in this build") from None


# --------------------------------------------------------------------------
# The script
# --------------------------------------------------------------------------


_HEADER = r"""# Newton's Active Directory build bootstrap.
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

$BuildDir = '@@BUILD_DIR@@'
$PasswordFile = '@@PASSWORD_FILE@@'
$InstallRoot = '@@INSTALL_ROOT@@'
$KeyFile = '@@KEY_FILE@@'
$DeviceFile = '@@DEVICE_FILE@@'
$HelperFile = '@@HELPER_FILE@@'
$KeysFile = '@@KEYS_FILE@@'
$SshdConfig = '@@SSHD_CONFIG@@'
$SshdBackup = '@@SSHD_BACKUP@@'
$BuildUser = '@@BUILD_USER@@'
$RestartTask = '@@RESTART_TASK@@'
$Device = @@DEVICE@@
$HostName = @@HOSTNAME@@
$Domain = @@DOMAIN@@

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
"""


_STEP_PRECHECK = r"""
Write-Host 'Step 1: the pre-checks'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'this script must run elevated, as an Administrator'
}
"""


_STEP_OPENSSH = r"""
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
"""


_STEP_ACCOUNT = r"""
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
"""


_STEP_KEYS = r"""
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
"""


_STEP_HELPER = r"""
Write-Host 'Step 5: the build helper and the key of the server'
# The install root of the helper holds the helper, K, the device name and
# the journal.  It is protected before K is written in it: a file of it
# inherits the rule of the directory.
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
Protect-NewtonPath -Path $InstallRoot -Inheritance 'ContainerInherit, ObjectInherit'
@@HELPER_BLOB@@
[System.IO.File]::WriteAllBytes($HelperFile, [System.Convert]::FromBase64String($helperB64))
# The helper finds this server in the plan by its device name.
[System.IO.File]::WriteAllText($DeviceFile, $Device + "`n", (New-Object System.Text.UTF8Encoding($false)))
@@OPS_TEMPLATES@@
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
"""


_STEP_ACL = r"""
Write-Host 'Step 6: the access control list'
Protect-NewtonPath -Path $BuildDir -Inheritance 'ContainerInherit, ObjectInherit'
Protect-NewtonPath -Path $PasswordFile -Inheritance 'None'
Protect-NewtonPath -Path $InstallRoot -Inheritance 'ContainerInherit, ObjectInherit'
Protect-NewtonPath -Path $KeyFile -Inheritance 'None'
Protect-NewtonPath -Path $DeviceFile -Inheritance 'None'
Protect-NewtonPath -Path $HelperFile -Inheritance 'None'
Protect-NewtonPath -Path $KeysFile -Inheritance 'None'
Write-Host 'The build directory, the install root of the helper and their files are protected: Administrators and SYSTEM have full control and nobody else.'
"""


_STEP_SSHD_CONFIG = r"""
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
    '@@BLOCK_MARKER@@'
    'Match User @@BUILD_USER@@,@@NETBIOS@@\@@BUILD_USER@@'
    '    AuthorizedKeysFile @@KEYS_FILE_SLASH@@'
    '    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File @@HELPER_FILE@@'
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
    if ([string]$line -eq '@@BLOCK_MARKER@@') {
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
"""


_STEP_SSHD_CHECK = r"""
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
"""


_STEP_FIREWALL = r"""
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
"""


_STEP_PROXMOX = r"""
Write-Host 'Step 10: the VirtIO serial driver and the QEMU guest agent'
# The guest agent needs the driver of the serial device: with the
# agent alone the service runs and the agent does not answer.
# The media is looked for on the CD-ROM volumes only: a user who is not
# an administrator may create a folder in C:\, and the driver and the
# agent are installed from the media elevated.
$isoRoot = $null
foreach ($disk in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=5')) {
    $letter = [string]$disk.DeviceID
    if (-not $letter) { continue }
    $root = $letter + '\'
    if ((Test-Path -LiteralPath (Join-Path $root 'vioserial')) -and (Test-Path -LiteralPath (Join-Path $root 'guest-agent'))) {
        $isoRoot = $root
        break
    }
}
if (-not $isoRoot) { throw 'the virtio-win media is not attached to this server' }
& pnputil.exe /add-driver (Join-Path $isoRoot 'vioserial\2k25\amd64\vioser.inf') /install
# 259 (ERROR_NO_MORE_ITEMS): the driver package is up to date on the
# device already (measured on BUILD1, 2026-11-18); it passes only when
# the device reads OK.
if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 3010) -and ($LASTEXITCODE -ne 259)) { throw 'the VirtIO serial driver was not installed' }
if ($LASTEXITCODE -eq 259) {
    $serial = @(Get-PnpDevice -PresentOnly -FriendlyName 'VirtIO Serial Driver' -ErrorAction SilentlyContinue)
    if (($serial.Count -lt 1) -or (@($serial | Where-Object { $_.Status -ne 'OK' }).Count -gt 0)) {
        throw 'the VirtIO serial driver was not installed'
    }
}
$msi = Join-Path $isoRoot 'guest-agent\qemu-ga-x86_64.msi'
$install = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', ('"' + $msi + '"'), '/qn', '/norestart') -Wait -PassThru
if (($install.ExitCode -ne 0) -and ($install.ExitCode -ne 3010)) { throw 'the QEMU guest agent was not installed' }
$agent = Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue
if (-not $agent) { throw 'the QEMU guest agent service is missing' }
Set-Service -Name 'QEMU-GA' -StartupType Automatic
if ($agent.Status -ne 'Running') { Start-Service -Name 'QEMU-GA' }
Write-Host 'The VirtIO serial driver is installed and the QEMU guest agent is running.'
"""


_STEP_RESTART = r"""
Write-Host 'Step @@RESTART_STEP@@: the sshd restart'
Unregister-ScheduledTask -TaskName $RestartTask -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Restart-Service sshd -Force; Unregister-ScheduledTask -TaskName ''@@RESTART_TASK@@'' -Confirm:$false"'
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


def render_bootstrap(plan: Mapping[str, Any], server: Any) -> str:
    """The script that sets one build server up.

    The plan is the plan the owner approved and the server is one of
    its servers (the role or the server itself).  The key K of the
    server is not an argument of the render and is not in the script:
    the owner types the passphrase of the build on the server, and the
    server derives K from it with the derivation of the approve
    module.  Whoever renders the script never holds K, so a Newton
    machine that is compromised cannot mint a token of the build
    without the owner's passphrase.

    The values of the plan are not checked against the grammar of the
    plan here, except the NetBIOS name, which reaches the
    configuration of sshd as the name of a user: they are the contents
    of single-quoted PowerShell strings, and a value that came from
    anywhere else stays inside its string.

    Raises ``BootstrapRefused`` with the code ``schema`` when the plan
    does not hold what the bootstrap needs, and with the code
    ``no_helper`` when the build helper is not in the build.
    """
    if not isinstance(plan, Mapping):
        raise _refuse("schema", "the plan is not an object")

    domain = _mapping(plan.get("domain"), "the domain of the plan")
    netbios = _text(domain.get("netbios"), "the NetBIOS name of the plan")
    if NETBIOS_RE.fullmatch(netbios) is None:
        raise _refuse("schema", "the NetBIOS name is not a NetBIOS name")
    dns_name = _text(domain.get("dns_name"), "the DNS name of the plan")
    one = _server_of(plan, server)
    device = _text(one.get("device"), "the device name of the server")
    hostname = _text(one.get("hostname"), "the hostname of the server")
    checkpoint = _text(one.get("checkpoint"), "the checkpoint method of the server")
    if checkpoint not in CHECKPOINT_METHODS:
        raise _refuse("schema", "the checkpoint method is not one of the three")
    helper = _helper_bytes()

    values: dict[str, str] = {
        "@@BUILD_DIR@@": BUILD_DIR,
        "@@PASSWORD_FILE@@": PASSWORD_FILE,
        "@@INSTALL_ROOT@@": INSTALL_ROOT,
        "@@KEY_FILE@@": KEY_FILE,
        "@@DEVICE_FILE@@": DEVICE_FILE,
        "@@HELPER_FILE@@": HELPER_FILE,
        "@@KEYS_FILE@@": KEYS_FILE,
        "@@KEYS_FILE_SLASH@@": KEYS_FILE.replace("\\", "/"),
        "@@SSHD_CONFIG@@": SSHD_CONFIG,
        "@@SSHD_BACKUP@@": SSHD_BACKUP,
        "@@BUILD_USER@@": BUILD_USER,
        "@@BLOCK_MARKER@@": BLOCK_MARKER,
        "@@RESTART_TASK@@": RESTART_TASK,
        "@@DEVICE@@": _literal(device, "the device name"),
        "@@HOSTNAME@@": _literal(hostname, "the hostname"),
        "@@DOMAIN@@": _literal(dns_name, "the DNS name"),
        "@@NETBIOS@@": _escape(netbios.lower(), "the NetBIOS name"),
        "@@HELPER_BLOB@@": _b64_literal("helperB64", helper),
        "@@OPS_TEMPLATES@@": _stage8_step(_text(one.get("role"), "the role of the server")),
    }

    parts = [
        _HEADER,
        _STEP_PRECHECK,
        _STEP_OPENSSH,
        _STEP_ACCOUNT,
        _STEP_KEYS,
        _STEP_HELPER,
        _STEP_ACL,
        _STEP_SSHD_CONFIG,
        _STEP_SSHD_CHECK,
        _STEP_FIREWALL,
    ]
    if checkpoint == "proxmox":
        parts.append(_STEP_PROXMOX)
    parts.append(_STEP_RESTART)
    values["@@RESTART_STEP@@"] = "11" if checkpoint == "proxmox" else "10"
    return _fill("".join(parts), values)
