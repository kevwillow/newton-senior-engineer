"""Generate the owner's setup script for an AD collector host (SPEC-1.3 section 9).

The script is printed, never run: the owner reads it and runs it as a
Domain Admin on the domain controller.  Every step of it is idempotent,
so a second run changes nothing the second time.

The Windows script does, in order:

1. the ``newton-audit`` account and its group membership;
2. the three collector files, written from base64 blobs that this
   module embeds, each one checked against the hash of the package file;
3. the access control list of the directory and of the three files,
   granted by SID and never by name;
4. the authorized key;
5. the sshd configuration, backed up once and restored when sshd
   refuses it;
6. the sshd restart, through a one-shot SYSTEM scheduled task;
7. the inventory entry.

The Samba script does, in order:

1. the ``newton-audit`` domain account, with a random password that
   samba-tool generates and nobody ever sees; the account is checked
   and never adopted, so a primary group that is not Domain Users, a
   membership in any group or a disabled account stops the script;
2. the local ``newton-ssh`` account, with no password at all, and its
   authorized key, whose only key line forces the collector; an account
   that exists already is checked and never adopted, so a home that is
   not the one of the key, a shell that is not ``/bin/sh``, a password
   that is not locked or a group besides the primary one stops the
   script; the home, its ``.ssh`` folder and the authorized key belong
   to root, and a file that is planted in ``.ssh`` stops the script;
3. the directories of the install, which must be owned by root and
   must not be writable by their group or by the others;
4. the three collector files, written from base64 blobs that this
   module embeds, each one checked against the hash of the package file
   and repaired when its mode or its owner is wrong;
5. the authorized key;
6. the sudoers drop-in that lets that account run the collector as
   root, checked with ``visudo -cf``; an existing file of the host
   that is not the one line of this script is never overwritten;
7. the inventory entry.

The sudoers line is the last thing the script writes: a run that stops
before it leaves no sudoers file behind, so a host that is not ready
never lets the account run the collector.

A file whose content is right is still repaired when its owner or its
mode is wrong.  The content of a file says what the file is, and the
owner and the mode say who may change it: the script reads the two
with ``stat -c '%U:%G %a'`` and installs the file again when either
differs from the owner and the mode of the install.

The two names of the Samba script are two accounts and not one.  The
domain account is ``newton-audit``: it is the account the audit runs
for, and the collector reports its ``objectSid`` and its
``tokenGroups`` as the identity of the document.  The local unix
account that logs in is ``newton-ssh``, because a Samba DC with
``passwd: files winbind`` resolves the domain account locally already
(measured on the lab DC on 2026-11-08): ``getent passwd newton-audit``
answers ``NEWTONLAB\\newton-audit:*:3000022:100::/home/NEWTONLAB/newton-audit:/bin/false``
and ``useradd newton-audit`` fails with "user 'newton-audit' already
exists".  The shell of the domain account is ``/bin/false``, so it is
never the account of a login.

The password of the audit account is generated inside the script from
32 random bytes.  It is never shown, never stored and never part of
this module's output.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import re
import sys
from pathlib import Path

from . import forbidden


# The files the Windows collector needs (SPEC-1.3 section 7).
COLLECTOR_PATH = Path(__file__).with_name("collector") / "collector.ps1"
QUERIES_PATH = Path(__file__).with_name("queries.json")

# The file the Samba collector needs (SPEC-1.3 section 7).  It is
# installed at /usr/local/sbin/newton-ad-samba.
SAMBA_COLLECTOR_PATH = Path(__file__).with_name("collector") / "newton-ad-samba"

# The key types the authorized_keys file may hold.
KEY_TYPES = ("ssh-ed25519", "ssh-rsa")

# The grammars of the values that reach the script.  They keep a quote,
# a dollar sign or a newline out of the PowerShell source.
DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
DEVICE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")

# The name of the one-shot task that restarts sshd.
RESTART_TASK = "Newton-Ad-SshdRestart"


class SetupError(Exception):
    """The setup script cannot be generated.

    The message names no secret and no file content.
    """


def _embedded_type(blob: bytes) -> str:
    """The key type the body of a key carries.

    The body of an OpenSSH public key is a sequence of length-prefixed
    fields and the first one is the type of the key.  A body that is not
    shaped that way carries no type at all.
    """
    if len(blob) < 4:
        return ""
    length = int.from_bytes(blob[:4], "big")
    if length > len(blob) - 4:
        return ""
    try:
        return blob[4 : 4 + length].decode("ascii")
    except UnicodeDecodeError:
        return ""


def validate_public_key(text: str) -> str:
    """The one public key line of an authorized_keys file.

    The line holds the key type, the base64 body and, optionally, the
    comment of the key; the comment is dropped, because it is not part
    of the key.  A line with options is refused, a key of another type
    is refused, a body that carries another type is refused, and a file
    with two lines is refused.  A single trailing newline is the normal
    end of a key file and is accepted.
    """
    if "\x00" in text:
        raise SetupError("the public key file holds a NUL")
    line = text
    if line.endswith("\r\n"):
        line = line[:-2]
    elif line.endswith("\n"):
        line = line[:-1]
    if "\n" in line or "\r" in line:
        raise SetupError("the public key file must hold exactly one key line")
    fields = line.split()
    if len(fields) not in (2, 3):
        raise SetupError(
            "the public key line must be the key type and the key body"
        )
    key_type, body = fields[0], fields[1]
    if key_type not in KEY_TYPES:
        raise SetupError("only an ssh-ed25519 or an ssh-rsa key is accepted")
    try:
        blob = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SetupError("the public key body is not base64") from exc
    if _embedded_type(blob) != key_type:
        raise SetupError("the public key body is not a key of that type")
    return f"{key_type} {body}"


def _read_public_key(path: Path) -> str:
    """The validated public key line of a file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SetupError(f"the public key file cannot be read: {path}") from exc
    except UnicodeDecodeError as exc:
        raise SetupError("the public key file is not UTF-8") from exc
    return validate_public_key(text)


def _sha256(data: bytes) -> str:
    """The hex sha256 of some bytes."""
    return hashlib.sha256(data).hexdigest()


def _b64_literal(name: str, data: bytes) -> str:
    """A PowerShell string that holds the base64 of some bytes."""
    encoded = base64.b64encode(data).decode("ascii")
    lines = [encoded[index : index + 120] for index in range(0, len(encoded), 120)]
    body = "\n".join(f"'{line}'" for line in lines)
    return f"${name} = @(\n{body}\n)\n${name} = ${name} -join ''"


def _b64_block(data: bytes) -> str:
    """The base64 of some bytes, in the lines a shell reads."""
    encoded = base64.b64encode(data).decode("ascii")
    return "\n".join(encoded[index : index + 76] for index in range(0, len(encoded), 76))


def windows_script(
    *,
    domain: str,
    pubkey: str,
    device: str,
    host: str,
) -> str:
    """The PowerShell script that sets one Windows collector host up.

    The public key is validated again here, so a caller that did not
    use ``validate_public_key`` cannot put a second field or an option
    into the script.
    """
    if DOMAIN_RE.fullmatch(domain) is None:
        raise SetupError("the domain must be a DNS name")
    if HOST_RE.fullmatch(host) is None:
        raise SetupError("the host must be a host name or an IP address")
    if DEVICE_RE.fullmatch(device) is None:
        raise SetupError("the device name must be [a-z][a-z0-9-]{0,31}")
    pubkey = validate_public_key(pubkey)

    collector = COLLECTOR_PATH.read_bytes()
    queries = QUERIES_PATH.read_bytes()
    forbidden_bytes = forbidden.dump_json()

    parts = [
        _HEADER.replace("@@DOMAIN@@", domain)
        .replace("@@DEVICE@@", device)
        .replace("@@HOST@@", host),
        _STEP_ACCOUNT,
        _STEP_FILES.replace("@@COLLECTOR@@", _b64_literal("collectorB64", collector))
        .replace("@@QUERIES@@", _b64_literal("queriesB64", queries))
        .replace("@@FORBIDDEN@@", _b64_literal("forbiddenB64", forbidden_bytes))
        .replace("@@HASH_COLLECTOR@@", _sha256(collector))
        .replace("@@HASH_QUERIES@@", _sha256(queries))
        .replace("@@HASH_FORBIDDEN@@", _sha256(forbidden_bytes)),
        _STEP_ACL,
        _STEP_KEY.replace("@@KEYLINE@@", pubkey),
        _STEP_SSHD,
        _STEP_RESTART,
        _STEP_INVENTORY.replace("@@DEVICE@@", device)
        .replace("@@HOST@@", host)
        .replace("@@DOMAIN@@", domain)
        .replace("@@KEYSHA@@", _sha256(pubkey.encode("utf-8"))),
    ]
    return "\n".join(parts)


def samba_script(
    *,
    domain: str,
    pubkey: str,
    device: str,
    host: str,
) -> str:
    """The bash script that sets one Samba collector host up.

    The script runs on the domain controller as root.  It creates the
    domain account, the local account that the key logs in as, the
    authorized key with its forced command, the one sudoers line that
    lets that account run the collector as root, and the three files of
    the collector.

    The domain account and the local account have different names, and
    they are two accounts: the domain account is ``newton-audit`` and
    the identity of the document, and the local account is
    ``newton-ssh``, the one the key logs in as.  They have to differ,
    because a Samba DC with ``passwd: files winbind`` resolves the
    domain account locally already and ``useradd newton-audit`` then
    fails with "user 'newton-audit' already exists".

    The public key is validated again here, so a caller that did not
    use ``validate_public_key`` cannot put a second field or an option
    into the script.  No password of any account is ever in the script:
    the password of the domain account is generated by samba-tool and
    the local account has none.
    """
    if DOMAIN_RE.fullmatch(domain) is None:
        raise SetupError("the domain must be a DNS name")
    if HOST_RE.fullmatch(host) is None:
        raise SetupError("the host must be a host name or an IP address")
    if DEVICE_RE.fullmatch(device) is None:
        raise SetupError("the device name must be [a-z][a-z0-9-]{0,31}")
    pubkey = validate_public_key(pubkey)

    collector = SAMBA_COLLECTOR_PATH.read_bytes()
    queries = QUERIES_PATH.read_bytes()
    forbidden_bytes = forbidden.dump_json()

    parts = [
        _SAMBA_HEADER.replace("@@DOMAIN@@", domain)
        .replace("@@DEVICE@@", device)
        .replace("@@HOST@@", host)
        .replace("@@KEYLINE@@", pubkey),
        _SAMBA_STEP_ACCOUNT,
        _SAMBA_STEP_LOCAL,
        _SAMBA_STEP_DIRECTORIES,
        _SAMBA_STEP_FILES.replace("@@COLLECTOR@@", _b64_block(collector))
        .replace("@@QUERIES@@", _b64_block(queries))
        .replace("@@FORBIDDEN@@", _b64_block(forbidden_bytes))
        .replace("@@HASH_COLLECTOR@@", _sha256(collector))
        .replace("@@HASH_QUERIES@@", _sha256(queries))
        .replace("@@HASH_FORBIDDEN@@", _sha256(forbidden_bytes)),
        _SAMBA_STEP_KEY,
        _SAMBA_STEP_SUDOERS,
        _SAMBA_STEP_INVENTORY.replace("@@DEVICE@@", device)
        .replace("@@HOST@@", host)
        .replace("@@DOMAIN@@", domain)
        .replace("@@KEYSHA@@", _sha256(pubkey.encode("utf-8"))),
    ]
    return "\n".join(parts)


_HEADER = """\
# Newton's Active Directory collector setup.
# Device: @@DEVICE@@   Host: @@HOST@@   Domain: @@DOMAIN@@
#
# Read this script, then run it as a Domain Admin on the domain
# controller.  Every step is idempotent: running it a second time
# changes nothing the second time.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Domain = '@@DOMAIN@@'
$Device = '@@DEVICE@@'
$CollectorHost = '@@HOST@@'
$AuditName = 'newton-audit'
$AdDir = 'C:\\ProgramData\\Newton\\ad'
$SshdConfig = 'C:\\ProgramData\\ssh\\sshd_config'
$SshdBackup = 'C:\\ProgramData\\ssh\\sshd_config.bak-newton'
$RestartTask = 'Newton-Ad-SshdRestart'
$BlockMarker = '# newton-ad collector'
"""

_STEP_ACCOUNT = """
Write-Host 'Step 1: the newton-audit account'
$user = Get-ADUser -Filter "SamAccountName -eq '$AuditName'"
if (-not $user) {
    $random = New-Object 'System.Byte[]' 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($random) } finally { $generator.Dispose() }
    $password = [Convert]::ToBase64String($random)
    $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
    $user = New-ADUser -Name $AuditName -SamAccountName $AuditName `
        -UserPrincipalName ($AuditName + '@' + $Domain) -AccountPassword $secure `
        -Enabled $true -PasswordNeverExpires $true
    $password = $null
    $secure = $null
    Write-Host 'Created newton-audit with a random password. It was not shown and it was not stored.'
} else {
    Write-Host 'newton-audit exists. Its password is left alone.'
    $memberOf = @()
    try {
        $memberOf = @((Get-ADUser -Filter "SamAccountName -eq '$AuditName'" -Properties MemberOf).MemberOf)
    } catch {
        $memberOf = @()
    }
    $groups = @($memberOf | Where-Object { $_ } | ForEach-Object { (Get-ADObject -Identity $_).Name })
    Write-Host ('newton-audit is in these groups: ' + ($groups -join ', '))
}
$openSshUsers = Get-ADGroup -Identity ('CN=OpenSSH Users,CN=Builtin,' + (Get-ADDomain).DistinguishedName)
$members = @(Get-ADGroupMember -Identity $openSshUsers -ErrorAction SilentlyContinue)
$isMember = $false
foreach ($member in $members) {
    $memberName = $member.PSObject.Properties['SamAccountName']
    if (($null -ne $memberName) -and ([string]$memberName.Value -eq $AuditName)) { $isMember = $true }
}
if (-not $isMember) {
    Add-ADGroupMember -Identity $openSshUsers -Members $AuditName
    Write-Host 'newton-audit is now a member of the domain-local OpenSSH Users group.'
} else {
    Write-Host 'newton-audit is already a member of the domain-local OpenSSH Users group.'
}
"""

_STEP_FILES = """
Write-Host 'Step 2: the collector files'
New-Item -ItemType Directory -Path $AdDir -Force | Out-Null
@@COLLECTOR@@
@@QUERIES@@
@@FORBIDDEN@@
[System.IO.File]::WriteAllBytes((Join-Path $AdDir 'collector.ps1'), [System.Convert]::FromBase64String($collectorB64))
[System.IO.File]::WriteAllBytes((Join-Path $AdDir 'queries.json'), [System.Convert]::FromBase64String($queriesB64))
[System.IO.File]::WriteAllBytes((Join-Path $AdDir 'forbidden.json'), [System.Convert]::FromBase64String($forbiddenB64))
$expected = @{
    'collector.ps1' = '@@HASH_COLLECTOR@@'
    'queries.json' = '@@HASH_QUERIES@@'
    'forbidden.json' = '@@HASH_FORBIDDEN@@'
}
foreach ($name in @('collector.ps1', 'queries.json', 'forbidden.json')) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $AdDir $name)).Hash.ToLowerInvariant()
    if ($hash -ne $expected[$name]) {
        throw ('the sha256 of ' + $name + ' does not match the package')
    }
    Write-Host ('sha256 ' + $name + ' ' + $hash)
}
"""

_STEP_ACL = """
Write-Host 'Step 3: the access control list'
$administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$auditUser = @(Get-ADUser -Filter "SamAccountName -eq '$AuditName'")
if ($auditUser.Count -ne 1) { throw 'the newton-audit account is missing' }
$auditSid = $auditUser[0].SID
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
$children = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$paths = @(
    @{ path = $AdDir; inheritance = $children },
    @{ path = (Join-Path $AdDir 'collector.ps1'); inheritance = $none },
    @{ path = (Join-Path $AdDir 'queries.json'); inheritance = $none },
    @{ path = (Join-Path $AdDir 'forbidden.json'); inheritance = $none }
)
foreach ($entry in $paths) {
    $acl = Get-Acl -LiteralPath $entry.path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    $acl.SetOwner($administrators)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $entry.inheritance, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $entry.inheritance, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($auditSid, 'ReadAndExecute', $entry.inheritance, $none, $allow)))
    Set-Acl -LiteralPath $entry.path -AclObject $acl
}
Write-Host 'The directory and the three files are protected: Administrators and SYSTEM have full control, newton-audit has read and execute.'
"""

_STEP_KEY = """
Write-Host 'Step 4: the authorized key'
$keyLine = 'restrict @@KEYLINE@@'
[System.IO.File]::WriteAllText((Join-Path $AdDir 'authorized_keys'), $keyLine + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
Write-Host 'The authorized key is written with the restrict option.'
"""

_STEP_SSHD = """
Write-Host 'Step 5: the sshd configuration'
if (-not (Test-Path -LiteralPath $SshdConfig)) { throw 'the sshd configuration is missing' }
if (-not (Test-Path -LiteralPath $SshdBackup)) {
    Copy-Item -LiteralPath $SshdConfig -Destination $SshdBackup -Force
    Write-Host 'The sshd configuration is backed up once, as .bak-newton.'
}
$config = Get-Content -LiteralPath $SshdConfig -Raw
$sshdChanged = $false
if ($config -notlike ('*' + $BlockMarker + '*')) {
    $netbios = ([string](Get-ADDomain).NetBIOSName).ToLowerInvariant()
    $blockLines = @(
        $BlockMarker
        ("Match User $($netbios)\\newton-audit")
        '    AuthorizedKeysFile __PROGRAMDATA__/Newton/ad/authorized_keys'
        '    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\ProgramData\\Newton\\ad\\collector.ps1'
        '    PermitTTY no'
        '    AllowTcpForwarding no'
        '    X11Forwarding no'
    )
    $block = ($blockLines -join "`n") + "`n"
    if (-not $config.EndsWith("`n")) { $block = "`n" + $block }
    [System.IO.File]::WriteAllText($SshdConfig, $config + $block, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $true
    Write-Host 'The collector block is in the sshd configuration.'
} else {
    Write-Host 'The collector block is already in the sshd configuration.'
}
$sshdExe = $null
$sshdCommand = Get-Command sshd.exe -ErrorAction SilentlyContinue
if ($sshdCommand) { $sshdExe = $sshdCommand.Source }
if (-not $sshdExe) {
    $candidate = Join-Path $env:WINDIR 'System32\\OpenSSH\\sshd.exe'
    if (Test-Path -LiteralPath $candidate) { $sshdExe = $candidate }
}
if (-not $sshdExe) {
    $candidate = Join-Path $env:ProgramFiles 'OpenSSH\\sshd.exe'
    if (Test-Path -LiteralPath $candidate) { $sshdExe = $candidate }
}
if (-not $sshdExe) {
    [System.IO.File]::WriteAllText($SshdConfig, $config, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $false
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
    [System.IO.File]::WriteAllText($SshdConfig, $config, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $false
    throw 'sshd refused the configuration. The configuration was put back.'
}
Write-Host 'sshd accepted the configuration.'
"""

_STEP_RESTART = """
Write-Host 'Step 6: the sshd restart'
Unregister-ScheduledTask -TaskName $RestartTask -Confirm:$false -ErrorAction SilentlyContinue
if ($sshdChanged) {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Restart-Service sshd -Force"'
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(8)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $RestartTask -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Host 'A one-shot SYSTEM task restarts sshd in 8 seconds. The session ends then.'
    Write-Host 'The task is removed by the next run of this script.'
} else {
    Write-Host 'The sshd configuration did not change. Nothing is restarted and no task is left behind.'
}
"""

_STEP_INVENTORY = """
Write-Host 'Step 7: the inventory entry'
Write-Host ''
Write-Host ('[devices.' + $Device + ']')
Write-Host 'platform = "ad-windows"'
Write-Host ('host = "' + $CollectorHost + '"')
Write-Host ('user = "newton-audit@' + $Domain + '"')
Write-Host 'experimental_readonly = true'
Write-Host 'key_file = "<the private key of the audit key, on the Newton host>"'
Write-Host 'known_hosts = "<the pinned known_hosts of the collector host>"'
Write-Host ('domain = "' + $Domain + '"')
Write-Host ''
Write-Host ('The installed public key (sha256): @@KEYSHA@@')
Write-Host 'The user principal name is the form the ssh client accepts. The domain\\user form is refused by the client.'
"""


# ---- the Samba script -------------------------------------------------------

_SAMBA_HEADER = """\
#!/usr/bin/env bash
# Newton's Active Directory collector setup (Samba).
# Device: @@DEVICE@@   Host: @@HOST@@   Domain: @@DOMAIN@@
#
# Read this script, then run it as root on the Samba domain
# controller.  Every step is idempotent: running it a second time
# changes nothing the second time.
#
# There are two accounts here, and they are not the same one:
#
#   newton-audit is the DOMAIN account.  The collector reports its
#   objectSid and its tokenGroups as the identity of the document.
#
#   newton-ssh is the LOCAL unix account that logs in.  It has no
#   password, so it cannot log in with one, and the forced command of
#   its key is the whole session.
#
# The two names have to differ.  A Samba DC with "passwd: files
# winbind" resolves the domain account locally already, so
# "getent passwd newton-audit" answers
#
#   NEWTONLAB\\newton-audit:*:3000022:100::/home/NEWTONLAB/newton-audit:/bin/false
#
# and "useradd newton-audit" fails with
# "user 'newton-audit' already exists" (exit 9).  The shell of the
# domain account is /bin/false, so it is never the account of a login
# anyway.  The local account therefore carries another name, and it is
# looked up with "getent -s files passwd newton-ssh": the files source
# only, so that winbind never answers for it.
#
# The script refuses instead of adopting.  An account that exists and
# is not the account of this script stops it, a domain account that is
# not the one of this script stops it, and a sudoers file that is not
# the one line of this script is never overwritten.
#
# The sudoers line is the last thing the script writes.  A run that
# stops before it leaves no sudoers file behind, so a host that is not
# ready never lets the account run the collector.
set -euo pipefail

DOMAIN='@@DOMAIN@@'
DEVICE='@@DEVICE@@'
COLLECTOR_HOST='@@HOST@@'
AUDIT_NAME='newton-audit'
LOGIN_NAME='newton-ssh'
SBIN_DIR='/usr/local/sbin'
LIB_DIR='/usr/local/lib/newton-ad'
COLLECTOR_PATH='/usr/local/sbin/newton-ad-samba'
QUERIES_PATH='/usr/local/lib/newton-ad/queries.json'
FORBIDDEN_PATH='/usr/local/lib/newton-ad/forbidden.json'
HOME_DIR='/var/lib/newton-ssh'
KEYFILE='/var/lib/newton-ssh/.ssh/authorized_keys'
SUDOERS_FILE='/etc/sudoers.d/newton-ssh'
SUDOERS_LINE='newton-ssh ALL=(root) NOPASSWD: /usr/local/sbin/newton-ad-samba ""'
KEY_LINE='restrict,command="sudo -n /usr/local/sbin/newton-ad-samba" @@KEYLINE@@'
WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

password_is_locked() {
    # $1 the account.  The password is locked when "passwd -S" says so,
    # or when the hash of the shadow file starts with "!" or "*".
    status="$(passwd -S "$1" 2>/dev/null | awk '{print $2}' || true)"
    if [ "${status}" = "L" ]; then
        return 0
    fi
    hash="$(awk -v name="$1:" '$1 == name {print $2}' /etc/shadow 2>/dev/null || true)"
    case "${hash}" in
    '!'*|'*'*) return 0 ;;
    esac
    return 1
}

check_root_directory() {
    # $1 the directory.  It must exist, it must be owned by root and it
    # must not be writable by its group or by the others.
    if [ ! -d "$1" ]; then
        echo "the directory $1 is missing" >&2
        exit 1
    fi
    mode="$(stat -c '%a' "$1")"
    owner="$(stat -c '%u' "$1")"
    if [ "${owner}" != "0" ]; then
        echo "the directory $1 is not owned by root" >&2
        exit 1
    fi
    case "${mode}" in
    ''|*[!0-7]*)
        echo "the mode of the directory $1 could not be read" >&2
        exit 1
        ;;
    esac
    # The mode of stat is an octal number, and the mask is one too.
    if [ $((0$mode & 022)) -ne 0 ]; then
        echo "the directory $1 may be written by its group or by the others" >&2
        exit 1
    fi
}

install_blob() {
    # $1 the file of the package, $2 the path to install it at, $3 the
    # mode, $4 the sha256 of the package file.  A file that is already
    # the file of the package is left alone, unless its mode or its
    # owner is wrong: then it is installed again, which repairs it.
    # The owner is the owner and the group, root:root, and not only
    # the owner of the file.
    if [ -f "$2" ] && [ "$(sha256sum "$2" | cut -d' ' -f1)" = "$4" ]; then
        blob_stat="$(stat -c '%U:%G %a' "$2")"
        blob_owner="${blob_stat%% *}"
        blob_mode="${blob_stat##* }"
        if [ "${blob_owner}" = "root:root" ] && [ "$((10#$blob_mode))" = "$((10#$3))" ]; then
            echo "  $2 is already the file of the package."
            return 0
        fi
        install -m "$3" -o root -g root "$1" "$2"
        echo "  $2 was repaired."
        return 0
    fi
    install -m "$3" -o root -g root "$1" "$2"
    echo "  $2 is installed."
}
"""

_SAMBA_STEP_ACCOUNT = """
echo "Step 1: the newton-audit domain account"
# The account is looked up with:
#   samba-tool user show newton-audit >/dev/null 2>&1
# It exits 0 when the account exists and 255 when it does not.  The
# names of the accounts are bare, one per line, and are never matched
# with a colon.
if samba-tool user show "${AUDIT_NAME}" >/dev/null 2>&1; then
    echo "  newton-audit exists. Its password is left alone."
else
    samba-tool user create "${AUDIT_NAME}" --random-password
    echo "  newton-audit was created with a random password. It was not shown and it was not stored."
fi
# The membership of the account is never changed here.  The primary
# group of a new account is Domain Users, and the account is not a
# member of it: Domain Users is its primary group and not a
# membership.  The check reads that group, and it is:
#   samba-tool user show newton-audit --attributes=primaryGroupID,memberOf,userAccountControl
# which prints "primaryGroupID: 513" and no memberOf line.
# The account is checked and never adopted: the group must be Domain
# Users, the account must not be a member of any group, and it must
# be enabled.
AUDIT_SHOW="$(samba-tool user show "${AUDIT_NAME}" --attributes=primaryGroupID,memberOf,userAccountControl 2>/dev/null || true)"
if ! printf '%s\\n' "${AUDIT_SHOW}" | grep -q '^primaryGroupID: 513$'; then
    echo "newton-audit's primary group is not Domain Users; fix it before running this again" >&2
    echo "newton-audit's primary group is not Domain Users; fix it before running this again"
    exit 1
fi
if printf '%s\\n' "${AUDIT_SHOW}" | grep -q '^memberOf:'; then
    echo "newton-audit is a member of a group; fix it before running this again" >&2
    echo "newton-audit is a member of a group; fix it before running this again"
    exit 1
fi
ACCOUNT_CONTROL="$(printf '%s\\n' "${AUDIT_SHOW}" | sed -n 's/^userAccountControl: //p' | head -n 1)"
case "${ACCOUNT_CONTROL}" in
''|*[!0-9]*)
    echo "the userAccountControl of newton-audit was not read; fix it before running this again" >&2
    exit 1
    ;;
esac
if [ $((ACCOUNT_CONTROL & 2)) -ne 0 ]; then
    echo "newton-audit is disabled; enable it before running this again" >&2
    echo "newton-audit is disabled; enable it before running this again"
    exit 1
fi
"""

_SAMBA_STEP_LOCAL = """
echo "Step 2: the local newton-ssh account"
# The account is looked up with:
#   getent -s files passwd newton-ssh
# The files source only: winbind answers for the domain account, and
# that account is not the one that logs in.
if getent -s files passwd "${LOGIN_NAME}" >/dev/null 2>&1; then
    echo "  the local account ${LOGIN_NAME} exists."
    # The account that exists must be the account of this script: the
    # home of the key, the shell of the forced command and a locked
    # password.  An account that is different is not adopted.
    PASSWD_ENTRY="$(getent -s files passwd "${LOGIN_NAME}")"
    ACCOUNT_HOME="$(printf '%s\\n' "${PASSWD_ENTRY}" | cut -d: -f6)"
    ACCOUNT_SHELL="$(printf '%s\\n' "${PASSWD_ENTRY}" | cut -d: -f7)"
    if [ "${ACCOUNT_HOME}" != "${HOME_DIR}" ]; then
        echo "the home of the local account ${LOGIN_NAME} is ${ACCOUNT_HOME}, not ${HOME_DIR}; it was not adopted" >&2
        exit 1
    fi
    if [ "${ACCOUNT_SHELL}" != "/bin/sh" ]; then
        echo "the shell of the local account ${LOGIN_NAME} is ${ACCOUNT_SHELL}, not /bin/sh; it was not adopted" >&2
        exit 1
    fi
    if ! password_is_locked "${LOGIN_NAME}"; then
        echo "the password of the local account ${LOGIN_NAME} is not locked; it was not adopted" >&2
        exit 1
    fi
else
    # The account is created by:
    #   useradd --home-dir /var/lib/newton-ssh --shell /bin/sh --password '!' newton-ssh
    useradd --home-dir "${HOME_DIR}" --shell /bin/sh --password '!' "${LOGIN_NAME}"
    echo "  the local account ${LOGIN_NAME} was created. It has no password, so it cannot log in with one."
fi
# The account must be in no group but its primary one.  A group of its
# own would give it a privilege the collector does not need, and the
# forced command of the key is the whole session anyway.
GROUP_COUNT=0
for group in $(id -Gn "${LOGIN_NAME}" 2>/dev/null || true); do
    GROUP_COUNT=$((GROUP_COUNT + 1))
done
if [ "${GROUP_COUNT}" -ne 1 ]; then
    echo "the local account ${LOGIN_NAME} is in ${GROUP_COUNT} group(s) and not in its primary group only; fix it before running this again" >&2
    exit 1
fi
# The home of the account and its .ssh folder belong to root: sshd
# reads the authorized key as root, and StrictModes accepts a file of
# the home of the account that root owns as long as neither its group
# nor the others may write it.
mkdir -p "${HOME_DIR}/.ssh"
chown root:root "${HOME_DIR}" "${HOME_DIR}/.ssh"
chmod 0755 "${HOME_DIR}"
chmod 0755 "${HOME_DIR}/.ssh"
# The .ssh folder holds the one file of this script and nothing else:
# a file that is planted there would be an authorized key of another
# kind, and it would survive the run.
for entry in "${HOME_DIR}/.ssh"/* "${HOME_DIR}/.ssh"/.[!.]*; do
    [ -e "${entry}" ] || continue
    if [ "${entry##*/}" != "authorized_keys" ]; then
        echo "the file ${entry} is not allowed in ${HOME_DIR}/.ssh; it was not adopted" >&2
        exit 1
    fi
done
"""

_SAMBA_STEP_DIRECTORIES = """
echo "Step 3: the directories of the install"
# The directory of the helper and the directory of the two files it
# runs must be owned by root and must not be writable by their group
# or by the others.  The check runs before anything is put in them and
# before the sudoers line is written: an unsafe directory stops the
# script with nothing installed and no sudoers line.
check_root_directory "${SBIN_DIR}"
install -d -m 0755 -o root -g root "${LIB_DIR}"
check_root_directory "${LIB_DIR}"
"""

_SAMBA_STEP_FILES = """
echo "Step 4: the collector files"
cat > "${WORK_DIR}/collector.b64" <<'NEWTON_AD_BLOB_EOF'
@@COLLECTOR@@
NEWTON_AD_BLOB_EOF
cat > "${WORK_DIR}/queries.b64" <<'NEWTON_AD_BLOB_EOF'
@@QUERIES@@
NEWTON_AD_BLOB_EOF
cat > "${WORK_DIR}/forbidden.b64" <<'NEWTON_AD_BLOB_EOF'
@@FORBIDDEN@@
NEWTON_AD_BLOB_EOF
base64 -d "${WORK_DIR}/collector.b64" > "${WORK_DIR}/newton-ad-samba"
base64 -d "${WORK_DIR}/queries.b64" > "${WORK_DIR}/queries.json"
base64 -d "${WORK_DIR}/forbidden.b64" > "${WORK_DIR}/forbidden.json"
install_blob "${WORK_DIR}/newton-ad-samba" "${COLLECTOR_PATH}" 0755 '@@HASH_COLLECTOR@@'
install_blob "${WORK_DIR}/queries.json" "${QUERIES_PATH}" 0644 '@@HASH_QUERIES@@'
install_blob "${WORK_DIR}/forbidden.json" "${FORBIDDEN_PATH}" 0644 '@@HASH_FORBIDDEN@@'
"""

_SAMBA_STEP_KEY = """
echo "Step 5: the authorized key"
printf '%s\\n' "${KEY_LINE}" > "${WORK_DIR}/authorized_keys"
if [ -f "${KEYFILE}" ] && cmp -s "${KEYFILE}" "${WORK_DIR}/authorized_keys"; then
    # The content of the key is the content of the script, but the
    # owner and the mode of the file may still be wrong: sshd reads
    # the key as root, and a file that another account owns or may
    # write is not the key of the script.  The file is installed again
    # when either is wrong, which repairs it.
    if [ "$(stat -c '%U:%G %a' "${KEYFILE}")" = "root:root 644" ]; then
        echo "  the authorized key is already in place."
    else
        install -m 0644 -o root -g root "${WORK_DIR}/authorized_keys" "${KEYFILE}"
        echo "  the authorized key was repaired. It forces the collector and nothing else."
    fi
else
    install -m 0644 -o root -g root "${WORK_DIR}/authorized_keys" "${KEYFILE}"
    echo "  the authorized key is written. It forces the collector and nothing else."
fi
"""

_SAMBA_STEP_SUDOERS = """
echo "Step 6: the sudoers line"
# The empty argument of the command is what allows the collector to
# run with no argument at all.  The line is checked with visudo before
# it is put in place, and an existing file of this host that is not
# this line is never overwritten.
#
# The line is the last thing the script does: a run that stops before
# it leaves no sudoers file behind, so a host that is not ready never
# lets the account run the collector.
SUDOERS_TMP='/etc/sudoers.d/.newton-ssh.newton'
printf '%s\\n' "${SUDOERS_LINE}" > "${SUDOERS_TMP}"
chmod 0440 "${SUDOERS_TMP}"
chown root:root "${SUDOERS_TMP}"
if visudo -cf "${SUDOERS_TMP}" >/dev/null; then
    if [ -f "${SUDOERS_FILE}" ] && ! cmp -s "${SUDOERS_FILE}" "${SUDOERS_TMP}"; then
        rm -f "${SUDOERS_TMP}"
        echo "the ${SUDOERS_FILE} of this host is not the line of this script. It was not overwritten." >&2
        exit 1
    fi
    # The content of the file is the line of the script, but the owner
    # and the mode of the file may still be wrong: sudo reads the file
    # as root, and a file that another account owns or may write is not
    # the line of the script.  The file is installed again when either
    # is wrong, which repairs it.
    if [ -f "${SUDOERS_FILE}" ] && [ "$(stat -c '%U:%G %a' "${SUDOERS_FILE}")" = "root:root 440" ]; then
        rm -f "${SUDOERS_TMP}"
        echo "  the sudoers line is already in place."
    else
        install -m 0440 -o root -g root "${SUDOERS_TMP}" "${SUDOERS_FILE}"
        rm -f "${SUDOERS_TMP}"
        echo "  the sudoers line is installed."
    fi
else
    rm -f "${SUDOERS_TMP}"
    echo "  visudo refused the sudoers line. Nothing was installed." >&2
    exit 1
fi
visudo -cf "${SUDOERS_FILE}"
"""

_SAMBA_STEP_INVENTORY = """
echo "Step 7: the inventory entry"

# The entry names the local account that logs in:
#   user = "newton-ssh"
cat <<EOF

[devices.${DEVICE}]
platform = "ad-samba"
host = "${COLLECTOR_HOST}"
user = "${LOGIN_NAME}"
experimental_readonly = true
key_file = "<the private key of the audit key, on the Newton host>"
known_hosts = "<the pinned known_hosts of the collector host>"
domain = "${DOMAIN}"

The installed public key (sha256): @@KEYSHA@@
The user is the local account ${LOGIN_NAME} of the controller: the key logs in as it, and the forced command runs the collector as root. The domain account is ${AUDIT_NAME}; winbind resolves it locally, so the local account carries another name.
EOF
"""


def _parser() -> argparse.ArgumentParser:
    """The command line of the setup tool."""
    parser = argparse.ArgumentParser(
        prog="newton-ad-setup",
        description=(
            "Print the owner's setup script for an Active Directory "
            "collector host. The script is printed, never run."
        ),
    )
    parser.add_argument(
        "platform",
        choices=("windows", "samba"),
        help="the collector platform to set up",
    )
    parser.add_argument(
        "--domain",
        required=True,
        help="the DNS name of the domain",
    )
    parser.add_argument(
        "--pubkey",
        required=True,
        help="the path of the public key of the audit key",
    )
    parser.add_argument(
        "--device",
        required=True,
        help="the name of the inventory device",
    )
    parser.add_argument(
        "--host",
        required=True,
        help="the host name or IP address of the collector host",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Print the setup script of one collector host."""
    args = _parser().parse_args(argv)
    try:
        pubkey = _read_public_key(Path(args.pubkey))
        if args.platform == "samba":
            script = samba_script(
                domain=args.domain,
                pubkey=pubkey,
                device=args.device,
                host=args.host,
            )
        else:
            script = windows_script(
                domain=args.domain,
                pubkey=pubkey,
                device=args.device,
                host=args.host,
            )
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: the collector files cannot be read: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(script)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
