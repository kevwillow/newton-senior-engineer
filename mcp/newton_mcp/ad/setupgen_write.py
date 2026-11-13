"""Generate the owner's setup script for the 1.4 write path (SPEC-1.4 section 8).

The script is printed, never run: the owner reads it and runs it as a
Domain Admin on the domain controller.  Every step of it is idempotent,
so a second run changes nothing the second time.

The script installs, on ONE domain controller:

1. the pre-checks, before any change at all: the script must be
   elevated, the host must be a domain controller of the domain and
   every delegated location must exist;
2. the ``newton-ops`` account, with a password that is generated inside
   the script and thrown away, with the bit that says the account may
   not be delegated, and with a refusal when its transitive groups hold
   a privileged group;
3. the delegation of SPEC-1.4 section 8, on the PDC only: the other
   domain controllers replicate it;
4. the approval key K, derived on the domain controller from the
   passphrase the owner types there, twice;
5. the files of section 8: the write helper, the device name and the
   transaction store;
6. the login: the authorized key, its access control list and the sshd
   block (Windows) or the sudoers line (Samba);
7. the keytab of the write identity (Samba) and the
   SeBatchLogonRight the undo task needs (Windows);
8. the inventory entry of this domain controller.

The sshd restart is the LAST step and it goes through a one-shot SYSTEM
task: a restart of sshd that is a child of the SSH session dies with
the session.

The delegation is written once, in the tables of this module, and both
scripts read them: the Windows script uses ``dsacls`` with an argv
array and the names dsacls takes, the Samba script uses
``samba-tool dsacl set`` with an SDDL it builds from the GUIDs it
reads from the schema of the domain at that moment.  No GUID of a
schema object is ever typed in a generated script.

The right of a password reset is an extended right and not an object of
the schema, and the GUID of it is the one exception to the rule above:
the Windows script reads the right from the extended rights of the
domain and refuses unless the GUID it read is the measured one, so the
value the directory is checked against is typed in the script.

The module also holds the ``approval-key`` command: it asks the owner
for the passphrase twice, derives K with ``derive_k`` and stores only
``approval_fingerprint(K)``, where ``newton-approve`` looks for it.  K
is never printed and never stored on this host.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from ..approve import approval_fingerprint, derive_k, state_dir
from .setupgen import (
    DEVICE_RE,
    DOMAIN_RE,
    HOST_RE,
    SetupError,
    validate_public_key,
)

# The two helpers that put a file into a generated script.  They are the
# ones of the 1.3 setup, unchanged.
from .setupgen import _b64_block as _b64_block
from .setupgen import _b64_literal as _b64_literal


# The write helper of the Windows platform (SPEC-1.4 section 8).  The
# file is built on another branch and merges in later; until then the
# setup says so and installs nothing.
WRITE_HELPER_PATH = Path(__file__).with_name("collector") / "write.ps1"

# The write helper of the Samba platform (SPEC-1.4 section 8).
SAMBA_WRITE_HELPER_PATH = (
    Path(__file__).with_name("collector") / "newton-ad-samba-write"
)

# The refusal of a build that does not carry the write helper.
NO_HELPER = "the write helper is not in this build"

# The domain account of the write path.
OPS_NAME = "newton-ops"

# The local account of the Samba login.
LOGIN_NAME = "newton-ops-ssh"

# The name of the one-shot task that restarts sshd.  It is not the name
# of the task of the 1.3 setup: both scripts may run on the same host.
RESTART_TASK = "Newton-Ad-Write-SshdRestart"

# The refusal of a session that cannot back the policy of the PDC up.
# The path of the policy is in the line: the owner has to see what the
# check measured.
#
# The rule is the measured one: an S4U session (an SSH key login) holds
# no ticket of the domain, and the backup of a policy over such a
# session is unreliable.  Measured on the real PDC on
# 2026-11-09: in a key session the read of the GPT.INI of the policy
# answered and the write of its template answered, and ``Backup-GPO``
# answered "Access is denied" (E_ACCESSDENIED), and the same code had
# passed over a key login earlier the same day.  The read of the share
# does not promise the backup, so the step 0 takes the backup itself
# and stops the run before any change when it cannot.
#
# ``{path}`` is the path of the policy of the PDC, and the script fills
# it in when it runs.
NO_POLICY_BACKUP = (
    "This session cannot back up the Default Domain Controllers Policy "
    "on the PDC ({path}), so the policy cannot be edited. Run this script "
    "on the PDC in a session with network credentials: an interactive "
    "logon, or a remote logon made with a password. An SSH key login "
    "(an S4U logon) cannot do this reliably."
)

# The module-level seam so a test can inject a fake reader instead of a
# terminal.
_getpass = getpass.getpass


#: The value of a distinguished name component.  It keeps a quote, a
#: dollar sign, a backslash and a newline out of the generated script,
#: which holds the name in a single-quoted string.
_RDN = r"[A-Za-z0-9][A-Za-z0-9 _.\-#&()]*"

#: A delegated location: one or more OU= or CN= components, then the
#: DC= components of the domain.
OU_DN_RE = re.compile(
    rf"^(?:(?:OU|CN)={_RDN},)+DC={_RDN}(?:,DC={_RDN})*$"
)

#: The relative identifiers of the privileged groups of SPEC-1.4
#: section 5, under the SID of any domain of the forest.
PRIVILEGED_RIDS: tuple[int, ...] = (
    498,
    512,
    516,
    518,
    519,
    520,
    521,
    525,
    526,
    527,
)

#: The privileged groups of the builtin domain (SPEC-1.4 section 5).
PRIVILEGED_BUILTIN_SIDS: tuple[str, ...] = (
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-552",
)


#: The delegation of SPEC-1.4 section 8: on every delegated location,
#: a write on these attributes of the objects of that class.
#:
#: The list is the one of the contract, and nothing more: a move needs
#: a write on ``name`` and on ``cn`` (measured 2026-11-09), a
#: user-create needs the create-child right, and the undo of a
#: user-create needs the delete-child right.
DELEGATED_PROPERTIES: tuple[tuple[str, str], ...] = (
    ("userAccountControl", "user"),
    ("msDS-SupportedEncryptionTypes", "user"),
    ("lockoutTime", "user"),
    ("name", "user"),
    ("cn", "user"),
    ("userAccountControl", "computer"),
    ("msDS-SupportedEncryptionTypes", "computer"),
    ("name", "computer"),
    ("cn", "computer"),
    ("member", "group"),
)

#: The create-child and delete-child rights of the delegation, per
#: class of child.
DELEGATED_CHILDREN: tuple[tuple[str, str], ...] = (
    ("create", "user"),
    ("delete", "user"),
    ("create", "computer"),
    ("delete", "computer"),
)

#: The SID of CREATOR OWNER.  The right of a password reset is granted
#: to it, and not to the write account: the write account may then set
#: the password of the accounts it creates, and of no other account.
#: An account that holds the right directly could reset the password
#: of any user of the location, and a password reset is a change
#: Newton never makes itself (SPEC-1.4 section 1).
CREATOR_OWNER_SID = "S-1-3-0"

#: The name of the extended right of a password reset.  The name of the
#: object is its CN ("User-Force-Change-Password") and its display name
#: is the one the directory shows ("Reset Password"): a lookup by the
#: display name finds nothing at all, as measured
#: on the real controller ("by name Reset Password: 0").
RESET_PASSWORD_RIGHT_CN = "User-Force-Change-Password"

#: The display name of the right of a password reset.  It is the name
#: the ace of dsacls carries, and that form was measured to work on
#: the real controller.  The GUID of the right is read from the
#: extended rights of the domain when the script runs: it is not an
#: object of the schema.
RESET_PASSWORD_RIGHT = "Reset Password"

#: The GUID of the right of a password reset.  The script reads it from
#: the extended rights of the domain and it refuses unless it is this
#: one: a right with another GUID is not the right of a password reset,
#: and the ace of dsacls would grant something else.
RESET_PASSWORD_GUID = "00299570-246d-11d0-a768-00aa006e0529"

#: The rights of the delegated locations that are granted to the
#: CREATOR OWNER and to nobody else.  A user-create with a secret sets
#: unicodePwd, and the directory checks the right of a password reset
#: of the creator of the object.  The right is inherited by the
#: descendants of the location, and it holds for the class of the
#: objects that the user-create makes.
CREATOR_RIGHTS: tuple[tuple[str, str], ...] = (
    (RESET_PASSWORD_RIGHT, "user"),
)

#: The attribute the domain head is given, and only it: the machine
#: account quota.  The right is not inherited.
HEAD_PROPERTY = "ms-DS-MachineAccountQuota"


def domain_dn(domain: str) -> str:
    """The distinguished name of the head of a domain."""
    if DOMAIN_RE.fullmatch(domain) is None:
        raise SetupError("the domain must be a DNS name")
    return ",".join(f"DC={label}" for label in domain.split("."))


def _domain_dc_parts(domain: str) -> list[str]:
    """The DC= components of the head of a domain."""
    return [f"DC={label}" for label in domain.split(".")]


def _ends_with_domain(ou: str, domain: str) -> bool:
    """True when a distinguished name ends in the DC= components of the
    domain, and in nothing else."""
    parts = ou.split(",")
    wanted = _domain_dc_parts(domain)
    if len(parts) <= len(wanted):
        return False
    head = parts[: len(parts) - len(wanted)]
    if any(part.upper().startswith("DC=") for part in head):
        return False
    tail = parts[len(parts) - len(wanted) :]
    for got, expect in zip(tail, wanted):
        if got.upper() != expect.upper():
            return False
    return True


def validate_ou(ou: str, domain: str) -> str:
    """The delegated location, when it may be delegated to.

    A delegated location is a distinguished name inside the domain: one
    or more OU= or CN= components, then the DC= components of the domain
    and nothing else.  The head of the domain is not a delegated
    location, and the OU of the domain controllers is not either: a
    write on the computer objects of that OU is a write on the account
    of a domain controller.
    """
    if not isinstance(ou, str) or not ou:
        raise SetupError("a delegated location must be a distinguished name")
    if "\n" in ou or "\r" in ou:
        raise SetupError("a delegated location must be one line")
    head = domain_dn(domain)
    if ou.upper() == head.upper():
        raise SetupError("the head of the domain is not a delegated location")
    if OU_DN_RE.fullmatch(ou) is None:
        raise SetupError(
            "a delegated location must be OU= or CN= components that end "
            "in the DC= components of the domain"
        )
    if not _ends_with_domain(ou, domain):
        raise SetupError(
            "a delegated location must be inside the domain the setup names"
        )
    if ou.upper() == f"OU=DOMAIN CONTROLLERS,{head.upper()}":
        raise SetupError(
            "the OU of the domain controllers is not a delegated location"
        )
    return ou


def validate_ous(ous: Sequence[str], domain: str) -> list[str]:
    """The delegated locations, when they may be delegated to."""
    if not ous:
        raise SetupError("at least one delegated location is needed")
    seen: list[str] = []
    for ou in ous:
        checked = validate_ou(ou, domain)
        if checked.upper() in [one.upper() for one in seen]:
            raise SetupError("the same delegated location was named twice")
        seen.append(checked)
    return seen


def _read_public_key(path: Path) -> str:
    """The validated public key line of a file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SetupError(f"the public key file cannot be read: {path}") from exc
    except UnicodeDecodeError as exc:
        raise SetupError("the public key file is not UTF-8") from exc
    return validate_public_key(text)


def _read_helper(path: Path) -> bytes:
    """The bytes of the write helper of the build."""
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SetupError(NO_HELPER) from exc


def _privileged_rids_text() -> str:
    """The privileged relative identifiers, for the generated scripts."""
    return ", ".join(str(rid) for rid in PRIVILEGED_RIDS)


def _privileged_builtin_text() -> str:
    """The privileged builtin groups, for the generated scripts."""
    return ", ".join(PRIVILEGED_BUILTIN_SIDS)


# ---- the approval key on this host ------------------------------------------


def fingerprint_path(device: str) -> Path:
    """The file the fingerprint of the key of a device lives in."""
    return state_dir() / "approval-fp" / device


def write_fingerprint(device: str, fingerprint: str) -> Path:
    """Write the fingerprint of the key of a device, and nothing else.

    The file is the one ``newton-approve`` looks for: it holds
    ``v1 <fingerprint>`` and nothing else.  K is never written here.
    """
    if DEVICE_RE.fullmatch(device) is None:
        raise SetupError("the device name must be [a-z][a-z0-9-]{0,31}")
    if not isinstance(fingerprint, str) or not re.fullmatch(
        r"[0-9a-f]{64}", fingerprint
    ):
        raise SetupError("the fingerprint must be 64 lowercase hexadecimal")
    path = fingerprint_path(device)
    parent = path.parent
    try:
        info = os.stat(parent.parent)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise SetupError(
            "the state directory cannot be inspected: "
            f"{parent.parent}"
        ) from exc
    else:
        if (stat.S_IMODE(info.st_mode) & 0o022) and not (
            info.st_mode & stat.S_ISVTX
        ):
            raise SetupError(
                "the state directory may be written by its group or by "
                "the others"
            )
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(parent, 0o700)
    # The old fingerprint goes before the new one: a write that fails
    # leaves the fingerprint missing, and a missing fingerprint is a
    # refusal, never a wrong one.
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(parent)
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(f"v1 {fingerprint}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    return path


def approval_key(device: str) -> int:
    """Ask for the passphrase of a device twice and store its fingerprint.

    The passphrase never reaches a file: K is derived from it, the
    fingerprint of K is written where ``newton-approve`` looks for it,
    and K itself is dropped.  An empty passphrase and two different
    passphrases are refusals, and nothing is written.
    """
    if DEVICE_RE.fullmatch(device) is None:
        raise SetupError("the device name must be [a-z][a-z0-9-]{0,31}")
    if not sys.stdin.isatty():
        raise SetupError("the approval passphrase must be read from a terminal")
    try:
        first = _getpass(f"approval passphrase for {device}: ")
        second = _getpass("approval passphrase again: ")
    except (EOFError, KeyboardInterrupt, OSError) as exc:
        raise SetupError("the approval passphrase could not be read") from exc
    if not first:
        raise SetupError("the approval passphrase must not be empty")
    if first != second:
        raise SetupError("the two approval passphrases do not match")
    passphrase = first.encode("utf-8")
    del first, second
    try:
        k_hex = derive_k(passphrase, device)
    finally:
        del passphrase
    fingerprint = approval_fingerprint(k_hex)
    del k_hex
    write_fingerprint(device, fingerprint)
    print(fingerprint)
    return 0


# ---- the Windows script ------------------------------------------------------


def windows_write_script(
    *,
    domain: str,
    pubkey: str,
    device: str,
    host: str,
    ous: Sequence[str],
    domain_device: str | None = None,
) -> str:
    """The PowerShell script that sets one Windows write host up.

    The public key is validated again here, so a caller that did not
    use ``validate_public_key`` cannot put a second field or an option
    into the script.  ``domain_device`` is the inventory name of the
    device that stands for the domain; without it the entry names the
    device of ``device``.
    """
    if DOMAIN_RE.fullmatch(domain) is None:
        raise SetupError("the domain must be a DNS name")
    if HOST_RE.fullmatch(host) is None:
        raise SetupError("the host must be a host name or an IP address")
    if DEVICE_RE.fullmatch(device) is None:
        raise SetupError("the device name must be [a-z][a-z0-9-]{0,31}")
    if domain_device is None:
        domain_device = device
    if DEVICE_RE.fullmatch(domain_device) is None:
        raise SetupError(
            "the domain device name must be [a-z][a-z0-9-]{0,31}"
        )
    pubkey = validate_public_key(pubkey)
    ous = validate_ous(ous, domain)
    helper = _read_helper(WRITE_HELPER_PATH)

    parts = [
        _WIN_HEADER.replace("@@DOMAIN@@", domain)
        .replace("@@DEVICE@@", device)
        .replace("@@DOMAIN_DEVICE@@", domain_device)
        .replace("@@HOST@@", host)
        .replace("@@DOMAIN_DN@@", domain_dn(domain))
        .replace("@@CREATOR_OWNER_SID@@", CREATOR_OWNER_SID)
        .replace("@@OUS@@", _win_ous_block(ous)),
        _WIN_FUNCTIONS.replace(
            "@@RESET_PASSWORD_RIGHT_CN@@", RESET_PASSWORD_RIGHT_CN
        )
        .replace("@@RESET_PASSWORD_RIGHT@@", RESET_PASSWORD_RIGHT)
        .replace("@@RESET_PASSWORD_GUID@@", RESET_PASSWORD_GUID),
        _WIN_STEP_PRECHECKS.replace("@@NO_BACKUP@@", _win_no_backup_line()),
        _WIN_STEP_ACCOUNT,
        _WIN_STEP_DELEGATION.replace(
            "@@PROPERTIES@@", _win_properties_block()
        )
        .replace("@@CHILDREN@@", _win_children_block())
        .replace("@@CREATOR@@", _win_creator_block()),
        _WIN_STEP_KEY,
        _WIN_STEP_FILES.replace(
            "@@HELPER@@", _b64_literal("helperB64", helper)
        ).replace("@@HELPER_HASH@@", _sha256(helper)),
        _WIN_STEP_LOGIN.replace("@@KEYLINE@@", pubkey),
        _WIN_STEP_BATCH_LOGON,
        _WIN_STEP_INVENTORY.replace("@@DEVICE@@", device)
        .replace("@@DOMAIN_DEVICE@@", domain_device)
        .replace("@@HOST@@", host)
        .replace("@@DOMAIN@@", domain)
        .replace("@@KEYSHA@@", _sha256(pubkey.encode("utf-8"))),
        _WIN_STEP_RESTART,
    ]
    return "\n".join(parts)


def _sha256(data: bytes) -> str:
    """The hex sha256 of some bytes."""
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _win_ous_block(ous: Sequence[str]) -> str:
    """The PowerShell array of the delegated locations."""
    lines = "\n".join(f"    '{ou}'" for ou in ous)
    return lines


def _win_no_backup_line() -> str:
    """The PowerShell that prints the refusal of the backup.

    The path of the policy of the PDC is in the line, and it is the
    path the script reads: the owner has to see what the check
    measured.
    """
    head, _, tail = NO_POLICY_BACKUP.partition("{path}")
    return f"('{head}' + $GptIniPath + '{tail}')"


def _win_properties_block() -> str:
    """The PowerShell table of the delegated property rights."""
    lines = []
    for attribute, klass in DELEGATED_PROPERTIES:
        lines.append(
            "    @{ right = 'WP'; objectType = 'property:"
            f"{attribute}'; inherited = '{klass}' }}"
        )
    return "\n".join(lines)


def _win_children_block() -> str:
    """The PowerShell table of the delegated child rights.

    The measured dsacls form grants the create-child and the
    delete-child right in ONE ace, ``CCDC``, so there is one row per
    class of child.
    """
    lines = []
    for klass in dict.fromkeys(klass for _, klass in DELEGATED_CHILDREN):
        lines.append(
            f"    @{{ right = 'CCDC'; objectType = '{klass}'; inherited = '' }}"
        )
    return "\n".join(lines)


def _win_creator_block() -> str:
    """The PowerShell table of the rights of the CREATOR OWNER.

    The right of a password reset is granted to the CREATOR OWNER of
    the objects of the location, and to nobody else.
    """
    lines = []
    for right, klass in CREATOR_RIGHTS:
        lines.append(
            f"    @{{ right = 'CA'; objectType = '{right}'; inherited = '{klass}' }}"
        )
    return "\n".join(lines)


_WIN_HEADER = """\
# Newton's Active Directory write setup (Windows).
# Device: @@DEVICE@@   Host: @@HOST@@   Domain: @@DOMAIN@@
#
# Read this script, then run it as a Domain Admin on the domain
# controller.  Every step is idempotent: running it a second time
# changes nothing the second time.
#
# The policy of the PDC is edited in the share of the SYSVOL of the
# PDC, and the backup of it is made on the PDC: the share of the name
# of the domain may be served by another controller, and the policy of
# the PDC is not there.
#
# An SSH key login is an S4U logon: it holds no ticket of the domain.
# Measured on the real PDC on 2026-11-09, in such a session the read of
# the GPT.INI of the policy answered and the write of its template
# answered, and Backup-GPO answered "Access is denied"
# (E_ACCESSDENIED), while the same code had passed over a key login
# earlier the same day.  The backup of a policy over an S4U session is
# unreliable, and the read of the GPT.INI does not promise it.
#
# The step 0 therefore reads the GPT.INI of the policy through the
# share of the PDC and backs the policy up itself, before any change:
# the step 6 uses that backup.  A run that cannot back the policy up
# stops in the step 0.  The run needs a session with network
# credentials: an interactive logon, or a remote logon made with a
# password.
#
# The pre-checks come first and they change nothing in the domain.  A
# run that stops in them leaves the domain as it was: the backup they
# take is a file on the disk of the controller.
#
# The delegation runs on the PDC only: the other domain controllers
# replicate it, so a run on another controller changes nothing there.
#
# The delegation of every delegated location holds one right more, for
# the CREATOR OWNER (@@CREATOR_OWNER_SID@@): the right of a password
# reset (Reset Password), on the user objects of the location.  A
# user-create with a secret sets unicodePwd, and the directory checks
# the right of a password reset of the creator of the object.  The
# right is granted to the CREATOR OWNER and not to newton-ops:
# newton-ops may then set the password of the accounts it creates, and
# of no other account, and a password reset is a change Newton never
# makes itself.
#
# That right is found by the CN of its object (User-Force-Change-
# Password), not by its display name (Reset Password): the name of an
# object of the directory is its CN, and a lookup by the display name
# finds nothing at all.  The script checks the display name and the
# GUID of the object before it uses the GUID, and it refuses when they
# are not the measured ones.
#
# The sshd restart is the last step, through a one-shot SYSTEM task: a
# restart of sshd that is a child of this session dies with the
# session.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$Domain = '@@DOMAIN@@'
$Device = '@@DEVICE@@'
$DomainDevice = '@@DOMAIN_DEVICE@@'
$WriteHost = '@@HOST@@'
$OpsName = 'newton-ops'
$DomainDn = '@@DOMAIN_DN@@'
$DcOuDn = 'OU=Domain Controllers,@@DOMAIN_DN@@'
$CreatorOwnerSid = '@@CREATOR_OWNER_SID@@'
# The container of the extended rights of this domain.  The right of a
# password reset lives there: it is not an object of the schema, and
# a search of the schema finds nothing at all.
$ExtendedRightsDn = 'CN=Extended-Rights,CN=Configuration,' + $DomainDn
$DelegatedOus = @(
@@OUS@@
)
$AdDir = 'C:\\ProgramData\\Newton\\ad'
$TxDir = 'C:\\ProgramData\\Newton\\ad\\tx'
$HelperPath = 'C:\\ProgramData\\Newton\\ad\\write.ps1'
$ApprovalKeyPath = 'C:\\ProgramData\\Newton\\ad\\approval.key'
$DeviceFilePath = 'C:\\ProgramData\\Newton\\ad\\device.txt'
$AuthorizedKeysPath = 'C:\\ProgramData\\Newton\\ad\\write_authorized_keys'
$SshdConfig = 'C:\\ProgramData\\ssh\\sshd_config'
$SshdBackup = 'C:\\ProgramData\\ssh\\sshd_config.bak-newton-write'
$RestartTask = 'Newton-Ad-Write-SshdRestart'
$BlockMarker = '# newton-ad write'
$GpoBackupRoot = 'C:\\ProgramData\\Newton\\ad\\gpo-backup'
$DefaultDcPolicyGuid = '6AC1786C-016F-11D2-945F-00C04fB984F9'
# The PDC of the domain, by its FQDN.  It is the answer of
# (Get-ADDomain).PDCEmulator.
$PdcServer = [string](Get-ADDomain).PDCEmulator
# The folder of the Default Domain Controllers Policy in the share of
# the SYSVOL of the PDC.  The share of the name of the domain is not
# used: it may be served by another controller.
$PdcPolicyDir = '\\\\' + $PdcServer + '\\SYSVOL\\' + $Domain + '\\Policies\\{' + $DefaultDcPolicyGuid + '}'
$GptIniPath = $PdcPolicyDir + '\\GPT.INI'
$GptTmplPath = $PdcPolicyDir + '\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf'
"""


_WIN_STEP_PRECHECKS = """
Write-Host 'Step 0: the pre-checks'

# The script must run with an Administrator token.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'this script must run elevated, as an Administrator'
}

# This host must be a domain controller of the domain the setup names.
$localDomain = Get-ADDomain
if ($localDomain.DNSName -ne $Domain) {
    throw ('this host is a domain controller of ' + $localDomain.DNSName + ', not of ' + $Domain)
}
$computer = $null
try { $computer = Get-ADComputer -Identity $env:COMPUTERNAME -ErrorAction Stop } catch { $computer = $null }
if (-not $computer) {
    throw 'the computer account of this host was not found'
}
# The computer account of a domain controller is
# CN=<name>,OU=Domain Controllers,<domain>: the OU of the controllers
# is the PARENT of the account, so it is read as the parent and not as
# a prefix of the name.
$computerParent = Get-DnParent $computer.DistinguishedName
if (-not $computerParent.Equals($DcOuDn, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'this host is not in the Domain Controllers OU of the domain'
}

# Every delegated location must exist.
foreach ($ou in $DelegatedOus) {
    $found = $null
    try { $found = Get-ADObject -Identity $ou -ErrorAction Stop } catch { $found = $null }
    if (-not $found) {
        throw ('the delegated location does not exist: ' + $ou)
    }
}

# The PDC of the domain is the controller whose rootDSE names the NTDS
# Settings object the head of the domain points at.  The delegation
# runs there only: the other controllers replicate it.
$rootDse = Get-ADRootDSE -Properties dsServiceName
$domainHead = Get-ADObject -SearchBase $DomainDn -SearchScope Base -LDAPFilter '(objectClass=domainDNS)' -Properties fSMORoleOwner, objectGuid
if (-not $domainHead) {
    throw 'the head of the domain was not found'
}
$isPdc = ([string]$rootDse.dsServiceName).Equals([string]$domainHead.fSMORoleOwner, [System.StringComparison]::OrdinalIgnoreCase)
if ($isPdc) {
    Write-Host 'This host holds the PDC emulator role of the domain.'
} else {
    Write-Host 'This host does not hold the PDC emulator role of the domain.'
}
# An entry that names its own device stands for the domain, and the
# domain has one device that stands for it: when another DC of the
# domain has an entry too, the loader of the inventory refuses the
# inventory and every change of the domain is refused.  The warning
# says so; the run goes on, because a domain device may be a
# controller that does not hold the role.
if (-not $isPdc -and $DomainDevice -eq $Device) {
    Write-Host 'WARNING: this DC does not hold the PDC emulator role and its entry names its own device. If another DC of the domain already has a write entry, run this setup again with --domain-device <that entry''s name>, or every change of the domain is refused.'
}

# The objectGUID of the head of the domain, read with the same base
# read that found the role owner.  The inventory entry of this
# controller carries it: the maq verb targets the head of the domain by
# that guid alone.
$DomainHeadGuid = ([guid]$domainHead.objectGuid).ToString()
if (-not $DomainHeadGuid) {
    throw 'the objectGUID of the head of the domain was not read'
}

# The session must be able to read the share of the SYSVOL of the
# PDC and to back the policy of the PDC up: the policy of the PDC is
# edited there, and the share of the name of the domain is not that
# one: it may be served by another controller.  An SSH key login is an
# S4U logon: it holds no ticket of the domain.  Over such a session
# the read of the GPT.INI of the policy may answer and Backup-GPO may
# fail with E_ACCESSDENIED, as measured on the real PDC
# on 2026-11-09, and the same code had passed over a key login
# earlier the same day.  The read does not promise the backup, so the
# step 0 makes the backup itself, before any change, and a session
# that cannot make it stops here.
#
# The check runs on the PDC only: the other controllers do not touch
# the policy at all.
if ($isPdc) {
    $gptIniReadable = $false
    try {
        $null = Get-Content -LiteralPath $GptIniPath -ErrorAction Stop
        $gptIniReadable = $true
    } catch {
        $gptIniReadable = $false
    }
    if (-not $gptIniReadable) {
        Write-Host @@NO_BACKUP@@
        exit 1
    }
    Write-Host 'This session can read the share of the PDC.'

    # The backup of the policy of the PDC, in a folder of its own named
    # after the time of the run: the step 6 uses it, and it takes no
    # other.  The cmdlet answers the policy it backed up: the object
    # goes to Out-Null, and the owner reads the one line of the step 6.
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $backupDir = Join-Path $GpoBackupRoot $stamp
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    try {
        Backup-GPO -Guid $DefaultDcPolicyGuid -Path $backupDir -Server $PdcServer -ErrorAction Stop | Out-Null
    } catch {
        Write-Host @@NO_BACKUP@@
        exit 1
    }
}
"""


_WIN_STEP_ACCOUNT = """
Write-Host 'Step 1: the newton-ops account'

$opsUsers = @(Get-ADUser -Filter "SamAccountName -eq '$OpsName'")
if ($opsUsers.Count -eq 0) {
    if (-not $isPdc) {
        # The account is created on the PDC and it reaches the other
        # controllers by replication.  Wait for it: a controller that
        # has not got it yet cannot install anything.
        $deadline = (Get-Date).AddMinutes(10)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 15
            $opsUsers = @(Get-ADUser -Filter "SamAccountName -eq '$OpsName'")
            if ($opsUsers.Count -gt 0) { break }
        }
        if ($opsUsers.Count -eq 0) {
            throw 'the newton-ops account has not reached this controller within 10 minutes; run this script again later'
        }
        Write-Host 'The newton-ops account reached this controller.'
    } else {
        # The password is generated here, from 32 random bytes, and it
        # is thrown away: it is never shown and it is never stored.  The
        # secure string is built one character at a time, so the
        # password is never a plain string either.
        $random = New-Object 'System.Byte[]' 32
        $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generator.GetBytes($random) } finally { $generator.Dispose() }
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        $secure = New-Object System.Security.SecureString
        foreach ($byte in $random) { $secure.AppendChar($alphabet[$byte % $alphabet.Length]) }
        $secure.MakeReadOnly()
        # The cmdlet has no -UserAccountControl, and it returns nothing
        # without -PassThru: the account is read again below.
        New-ADUser -Name $OpsName -SamAccountName $OpsName `
            -UserPrincipalName ($OpsName + '@' + $Domain) -AccountPassword $secure `
            -Enabled $true -PasswordNeverExpires $true | Out-Null
        Write-Host 'newton-ops was created with a random password. It was not shown and it was not stored.'
    }
}
# The account is read with its userAccountControl: the cmdlet does not
# answer it otherwise, and a value that cannot be read is a refusal.
$opsUser = Get-ADUser -Identity $OpsName -Properties userAccountControl
$opsDn = $opsUser.DistinguishedName
$opsSid = [string]$opsUser.SID

# The groups of the account are read with a search whose scope is
# Base, on the account itself: the groups of an object are a
# constructed attribute, and the directory gives them only to a read
# of that kind.  A read of any other scope is refused by the directory
# itself, with the error 8480 of the server, as measured
# on the real controller, where the run of the script before the
# account-read fix stopped right after this step.  The write helper of
# this platform reads them the same way (write.ps1, the read of the
# account of the helper).
#
# The groups are read before any change of this step, and a read that
# answers nothing is a refusal.
$groupObjects = @(Get-ADObject -SearchBase $opsUser.DistinguishedName -SearchScope Base -Filter '*' -Properties tokenGroups)
$tokenProperty = $null
if ($groupObjects.Count -eq 1) {
    $tokenProperty = $groupObjects[0].PSObject.Properties['tokenGroups']
}
if (($null -eq $tokenProperty) -or ($null -eq $tokenProperty.Value)) {
    throw 'the groups of newton-ops could not be read; nothing after this point was changed'
}
$tokenGroups = @($tokenProperty.Value)
if ($tokenGroups.Count -eq 0) {
    throw 'the groups of newton-ops could not be read; nothing after this point was changed'
}

$uacProperty = $opsUser.PSObject.Properties['userAccountControl']
if (($null -eq $uacProperty) -or ($null -eq $uacProperty.Value)) {
    throw 'the userAccountControl of newton-ops could not be read'
}
$currentUac = [int]$uacProperty.Value
if ($currentUac -eq 0) {
    throw 'the userAccountControl of newton-ops is 0'
}

# The account may not be delegated: the bit 0x100000 of the
# userAccountControl.  The bit is ADDED to the value that is there:
# the value is never replaced, or the NORMAL_ACCOUNT bit of the
# account would be dropped.
$wantedUac = $currentUac -bor 0x100000
if ($wantedUac -ne $currentUac) {
    Set-ADObject -Identity $opsDn -Replace @{ userAccountControl = $wantedUac }
    Write-Host 'newton-ops may not be delegated.'
}

# The transitive groups of the account may hold no privileged group.
# The set is the one of SPEC-1.4 section 5: the relative identifiers
# of the privileged groups of any domain of the forest, and the
# privileged groups of the builtin domain.
foreach ($groupSid in $tokenGroups) {
    if (Test-PrivilegedSid $groupSid) {
        throw ('newton-ops holds a privileged group (' + $groupSid + '); fix it before running this script again')
    }
}
Write-Host ('newton-ops is in ' + $tokenGroups.Count + ' group(s) and none of them is privileged.')

# The account may hold no right that replicates the directory.  That
# check is the check of AD-A-51 of SPEC-1.3, run against newton-ops.
Test-NoReplicationRight $opsSid $tokenGroups

# The effective trustees of newton-ops may not hold the right of a
# password reset, every extended right, or GenericAll on a delegated
# location or explicitly on an object below it. tokenGroups is
# transitive but omits Everyone and Authenticated Users, so include
# both well-known SIDs. This runs after the account exists on every run
# and before any delegation is changed.
$resetTrustees = @($opsSid) + @($tokenGroups) + @('S-1-1-0', 'S-1-5-11')
$resetPasswordGuid = Get-ResetPasswordGuid $ExtendedRightsDn
foreach ($ou in $DelegatedOus) {
    Test-NoResetPasswordRight $ou $resetTrustees $resetPasswordGuid | Out-Null
}
Write-Host 'newton-ops holds no effective right of a password reset.'
"""


_WIN_STEP_DELEGATION = """
Write-Host 'Step 2: the delegation'
if (-not $isPdc) {
    Write-Host 'delegation: done on the PDC'
} else {
    # The GUIDs of the classes and of the attributes are read from the
    # schema of this domain, at this moment, one object at a time and
    # by its LDAP display name.  No GUID of a schema object is typed in
    # this script.
    $schemaDn = 'CN=Schema,CN=Configuration,' + $DomainDn
    $delegatedRights = @(
@@PROPERTIES@@
@@CHILDREN@@
@@CREATOR@@
    )
    foreach ($ou in $DelegatedOus) {
        foreach ($row in $delegatedRights) {
            if ($row.right -eq 'WP') {
                # The right of a property of the objects of a class.
                $attributeName = $row.objectType.Substring('property:'.Length)
                $className = $row.inherited
                $objectTypeGuid = Get-SchemaGuid $schemaDn $attributeName 'attributeSchema'
                $inheritedGuid = Get-SchemaGuid $schemaDn $className 'classSchema'
                $ace = $opsSid + ':WP;' + $attributeName + ';' + $className
                # The measured form: the property right is inherited by
                # the children of the location and not by the location
                # itself.
                $dsaclsArgs = @($ou, '/I:S', '/G', $ace)
                $wantedRights = 'WriteProperty'
                $wantedInheritance = 'Descendents'
                $trustee = $opsSid
            } elseif ($row.right -eq 'CA') {
                # The right of a password reset, for the CREATOR OWNER
                # and for nobody else.  A user-create with a secret
                # sets unicodePwd, and the directory checks the right
                # of a password reset of the creator of the object.
                # The right is granted to the CREATOR OWNER, so that
                # the write account may set the password of the
                # accounts it creates and of no other account: an
                # account that holds the right directly could reset
                # the password of any user of the location, and a
                # password reset is a change Newton never makes
                # itself.
                #
                # The GUID of the right is read by the CN of the
                # object, and the ace carries the DISPLAY name of it:
                # the ace of dsacls takes the display name, and that
                # form was measured to work on the real controller.
                $className = $row.inherited
                $objectTypeGuid = Get-ResetPasswordGuid $ExtendedRightsDn
                $inheritedGuid = Get-SchemaGuid $schemaDn $className 'classSchema'
                $ace = $CreatorOwnerSid + ':CA;' + $row.objectType + ';' + $className
                $dsaclsArgs = @($ou, '/I:S', '/G', $ace)
                $wantedRights = 'ExtendedRight'
                $wantedInheritance = 'Descendents'
                $trustee = $CreatorOwnerSid
            } else {
                # The right of the children of a class: the
                # create-child and the delete-child right in one ace.
                $className = $row.objectType
                $objectTypeGuid = Get-SchemaGuid $schemaDn $className 'classSchema'
                $inheritedGuid = [string][System.Guid]::Empty
                $ace = $opsSid + ':CCDC;' + $className
                $dsaclsArgs = @($ou, '/I:T', '/G', $ace)
                $wantedRights = 'CreateChild, DeleteChild'
                $wantedInheritance = 'All'
                $trustee = $opsSid
            }
            if (Test-AcePresent $ou $trustee $wantedRights $objectTypeGuid $inheritedGuid $wantedInheritance) {
                Write-Host ('  ' + $row.right + ' ' + $row.objectType + ' of ' + $ou + ' is present')
            } else {
                # dsacls is run with an argv array: the name of the
                # object is never a part of a command string.  It
                # prints the WHOLE access control list of the object,
                # so the output is captured and it is printed only when
                # the call failed.  The error preference is lowered for
                # the call: a native command that writes to its error
                # stream would otherwise stop the script before its
                # output was read.
                $savedPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                try {
                    $out = & dsacls @dsaclsArgs 2>&1
                } finally {
                    $ErrorActionPreference = $savedPreference
                }
                if ($LASTEXITCODE -ne 0) {
                    Write-Host ('dsacls said: ' + (($out | ForEach-Object { [string]$_ }) -join ' '))
                    throw ('dsacls refused the ACE ' + $ace + ' on ' + $ou)
                }
                # The ACE is read back: a grant that is not the one
                # that was asked for is a refusal.
                if (-not (Test-AcePresent $ou $trustee $wantedRights $objectTypeGuid $inheritedGuid $wantedInheritance)) {
                    throw ('the ACE ' + $ace + ' on ' + $ou + ' is not there after the grant')
                }
                Write-Host ('  ' + $row.right + ' ' + $row.objectType + ' of ' + $ou + ' is added')
            }
        }
    }
    # The head of the domain gets one right of its own, and it is not
    # inherited: the machine account quota.
    $headGuid = Get-SchemaGuid $schemaDn 'ms-DS-MachineAccountQuota' 'attributeSchema'
    $headAce = $opsSid + ':WP;ms-DS-MachineAccountQuota'
    $headInherited = [string][System.Guid]::Empty
    if (Test-AcePresent $DomainDn $opsSid 'WriteProperty' $headGuid $headInherited 'None') {
        Write-Host ('  WP property:ms-DS-MachineAccountQuota of ' + $DomainDn + ' is present')
    } else {
        $dsaclsArgs = @($DomainDn, '/G', $headAce)
        # The output of dsacls is captured and printed only when the
        # call failed: the whole access control list of the object is
        # of no use to the owner of the domain.
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $out = & dsacls @dsaclsArgs 2>&1
        } finally {
            $ErrorActionPreference = $savedPreference
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Host ('dsacls said: ' + (($out | ForEach-Object { [string]$_ }) -join ' '))
            throw ('dsacls refused the ACE ' + $headAce + ' on ' + $DomainDn)
        }
        if (-not (Test-AcePresent $DomainDn $opsSid 'WriteProperty' $headGuid $headInherited 'None')) {
            throw ('the ACE ' + $headAce + ' on ' + $DomainDn + ' is not there after the grant')
        }
        Write-Host ('  WP property:ms-DS-MachineAccountQuota of ' + $DomainDn + ' is added')
    }
}
"""


_WIN_FUNCTIONS = """
# The helpers of this script.  They are here, and not in the middle of
# a step, so that a step reads as the steps of the contract.

function Get-DnParent([string]$Dn) {
    # The parent of a distinguished name: everything after the first
    # comma that is not escaped.  A comma of a name is written "\\,".
    $escaped = $false
    for ($index = 0; $index -lt $Dn.Length; $index++) {
        $character = $Dn[$index]
        if ($escaped) { $escaped = $false; continue }
        if ($character -eq '\\') { $escaped = $true; continue }
        if ($character -eq ',') { return $Dn.Substring($index + 1) }
    }
    return ''
}

function Test-PrivilegedSid([string]$Sid) {
    # The privileged set of SPEC-1.4 section 5: the relative
    # identifiers of the privileged groups of any domain of the forest,
    # and the privileged groups of the builtin domain.  The tokenGroups
    # of an account are transitive, so a group that is nested in a
    # privileged group is in the list too.
    foreach ($builtin in @('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551', 'S-1-5-32-552')) {
        if ($Sid -eq $builtin) { return $true }
    }
    if (-not $Sid.StartsWith('S-1-5-21-')) { return $false }
    $parts = $Sid.Split('-')
    if ($parts.Count -lt 5) { return $false }
    $rid = 0
    if (-not [int]::TryParse($parts[$parts.Count - 1], [ref]$rid)) { return $false }
    foreach ($privileged in @(498, 512, 516, 518, 519, 520, 521, 525, 526, 527)) {
        if ($rid -eq $privileged) { return $true }
    }
    return $false
}

function Get-SchemaGuid([string]$SchemaDn, [string]$DisplayName, [string]$Class) {
    # The GUID of a schema object, read by its LDAP display name.  The
    # name of a schema object is its CN ("User-Account-Control") and
    # the display name is the one the directory uses
    # ("userAccountControl"), so the name never finds the object.
    # Only the objects that are needed are read.
    #
    # The schemaIDGUID of the directory is a BYTE ARRAY and not a
    # string: a string of it is "104 122 150 191 230 13 208 17 162
    # 133 0 170 0 48 73 226", and it never matches the GUID of the
    # rule of an object.  The bytes are turned into a GUID, and the
    # GUID is what is kept.
    if (-not (Test-Path 'variable:script:NewtonSchemaGuids')) {
        $script:NewtonSchemaGuids = @{}
    }
    $key = $Class + '|' + $DisplayName
    if ($script:NewtonSchemaGuids.ContainsKey($key)) {
        return [string]$script:NewtonSchemaGuids[$key]
    }
    $objects = @(Get-ADObject -SearchBase $SchemaDn -SearchScope Subtree -LDAPFilter "(lDAPDisplayName=$DisplayName)" -Properties schemaIDGUID, objectClass)
    foreach ($object in $objects) {
        if (@($object.objectClass) -contains $Class) {
            $script:NewtonSchemaGuids[$key] = ([guid][byte[]]$object.schemaIDGUID).ToString()
            return [string]$script:NewtonSchemaGuids[$key]
        }
    }
    throw ('the schema of this domain holds no ' + $Class + ' named ' + $DisplayName)
}

function Get-AclRules([string]$Dn) {
    # The rules of the access control list of an object of the
    # directory.  The rules are read as objects and not as SDDL text:
    # the text prints the masks as letters and the trustees as names,
    # and a comparison of that text never matches.
    #
    # GetAccessRules takes the inherited rules first and the explicit
    # ones second: ($true, $false) answers every rule of the object.
    $object = Get-ADObject -Identity $Dn -Properties nTSecurityDescriptor
    return @($object.nTSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
}

function Get-DelegatedObjects([string]$Ou) {
    # The objects below a delegated location, with the rules of their
    # access control lists.  The guard of the right of a password reset
    # reads them: an account that holds the right on an object below
    # the location holds it on that object.
    $found = @()
    foreach ($object in @(Get-ADObject -SearchBase $Ou -SearchScope Subtree -LDAPFilter '(objectClass=*)' -Properties nTSecurityDescriptor)) {
        if ([string]$object.DistinguishedName -eq $Ou) { continue }
        $found += $object
    }
    return $found
}

function Get-ResetPasswordGuid([string]$ExtendedRightsDn) {
    # The GUID of the right of a password reset, read from the
    # extended rights of this domain.  The rights that are not rights
    # of the schema live under CN=Extended-Rights, and a search of the
    # schema finds nothing at all.
    #
    # The right is found by its CN ("@@RESET_PASSWORD_RIGHT_CN@@"): the
    # name of the object is its CN, and the display name of the object
    # is another attribute, so a lookup by the display name finds
    # nothing at all.  Measured on the real
    # controller: "by name Reset Password: 0".
    #
    # The object is checked before its GUID is used: the display name
    # and the GUID have to be the measured ones, or the run is refused.
    # A right with another GUID is not the right of a password reset.
    foreach ($right in @(Get-ADObject -SearchBase $ExtendedRightsDn -SearchScope OneLevel -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGuid, displayName)) {
        if ([string]$right.name -ne '@@RESET_PASSWORD_RIGHT_CN@@') { continue }
        $displayName = $right.PSObject.Properties['displayName']
        $shown = ''
        if ($null -ne $displayName) { $shown = [string]$displayName.Value }
        if ($shown -ne '@@RESET_PASSWORD_RIGHT@@') {
            throw ('the right of a password reset of this domain has the display name "' + $shown + '" and not "@@RESET_PASSWORD_RIGHT@@"')
        }
        $guid = $right.PSObject.Properties['rightsGuid']
        if ($null -eq $guid) {
            throw 'the right of a password reset of this domain holds no GUID'
        }
        $value = ([string]$guid.Value).ToLowerInvariant()
        if ($value -ne '@@RESET_PASSWORD_GUID@@') {
            throw ('the right of a password reset of this domain has the GUID "' + $value + '" and not "@@RESET_PASSWORD_GUID@@"')
        }
        return $value
    }
    throw 'the extended rights of this domain hold no right named @@RESET_PASSWORD_RIGHT_CN@@'
}

function Test-NoResetPasswordRule([string]$Dn, [object[]]$Rules, [string[]]$TrusteeSids, [string]$ResetGuid, [string]$Ou) {
    # The rules of one object, and the right of a password reset.  The
    # rules are read as objects and not as SDDL text: the text prints
    # the trustees as names, and a comparison of that text never
    # matches.
    foreach ($rule in $Rules) {
        if ($TrusteeSids -notcontains [string]$rule.IdentityReference.Value) { continue }
        if ([string]$rule.AccessControlType -ine 'Allow') { continue }
        $rights = [System.DirectoryServices.ActiveDirectoryRights]$rule.ActiveDirectoryRights
        $genericAll = (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
        $extended = (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)
        $objectType = ([string]$rule.ObjectType).ToLowerInvariant()
        $allExtended = ($objectType -eq ([System.Guid]::Empty).ToString())
        if (-not ($genericAll -or ($extended -and (($objectType -eq $ResetGuid) -or $allExtended)))) { continue }
        throw ('newton-ops holds an effective right of a password reset on ' + $Dn + ', under the delegated location ' + $Ou + '; fix it before running this script again')
    }
}

function Test-NoResetPasswordRight([string]$Ou, [string[]]$TrusteeSids, [string]$ResetGuid) {
    # The write account may not hold the right of a password reset, and
    # it may not hold it on an object below a delegated location
    # either.  The setup grants that right to the CREATOR OWNER, so
    # that the write account may set the password of the accounts it
    # creates and of no other account: an account that holds the right
    # directly could reset the password of any user of the location,
    # and a password reset is a change Newton never makes itself.
    #
    # The rules of the location are read with the inherited ones: a
    # right that the location inherits is a right that the location
    # holds.  The rules of the objects below it are read without the
    # inherited ones: the CREATOR OWNER of an object that newton-ops
    # creates is newton-ops itself, and that is the scope of the grant,
    # not a refusal.
    #
    # GetAccessRules takes the inherited rules first and the explicit
    # ones second: ($true, $false) answers every rule of the object,
    # and ($false, $true) answers the explicit rules only.
    $location = Get-ADObject -Identity $Ou -Properties nTSecurityDescriptor
    $rules = @($location.nTSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    Test-NoResetPasswordRule $Ou $rules $TrusteeSids $ResetGuid $Ou
    foreach ($object in (Get-DelegatedObjects $Ou)) {
        $dn = [string]$object.DistinguishedName
        $rules = @($object.nTSecurityDescriptor.GetAccessRules($false, $true, [System.Security.Principal.SecurityIdentifier]))
        Test-NoResetPasswordRule $dn $rules $TrusteeSids $ResetGuid $Ou
    }
}

function Test-AcePresent([string]$Dn, [string]$Sid, [string]$Rights, [string]$ObjectType, [string]$InheritedType, [string]$InheritanceType) {
    # True when the descriptor holds exactly this rule.  The fields of
    # the rule are the ones measured on the domain controller: the
    # rights, the object type, the inherited object type, the
    # inheritance and the trustee.
    $objectAceType = [int][System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent
    $inheritedObjectAceType = [int][System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent
    foreach ($rule in (Get-AclRules $Dn)) {
        if ([string]$rule.IdentityReference.Value -ne $Sid) { continue }
        if (([string]$rule.ActiveDirectoryRights) -ine $Rights) { continue }
        if (([string]$rule.ObjectType) -ine $ObjectType) { continue }
        if (([string]$rule.InheritedObjectType) -ine $InheritedType) { continue }
        if (([string]$rule.InheritanceType) -ine $InheritanceType) { continue }
        $flags = [int]$rule.ObjectFlags
        if (($flags -band $objectAceType) -eq 0) { continue }
        if ($InheritedType -ne [string][System.Guid]::Empty) {
            if (($flags -band $inheritedObjectAceType) -eq 0) { continue }
        }
        return $true
    }
    return $false
}

function Test-NoReplicationRight([string]$Sid, [string[]]$GroupSids) {
    # The account may hold no right that replicates the directory.  The
    # rights that replicate are extended rights: controlAccessRight
    # objects under CN=Extended-Rights,CN=Configuration of this domain.
    # They are not objects of the schema, and a search of the schema
    # finds nothing at all.  No GUID of a schema object is typed in
    # this script.
    $extendedRightsDn = 'CN=Extended-Rights,CN=Configuration,' + $DomainDn
    $wanted = @(
        'DS-Replication-Get-Changes',
        'DS-Replication-Get-Changes-All',
        'DS-Replication-Get-Changes-In-Filtered-Set'
    )
    $found = @{}
    foreach ($right in (Get-ADObject -SearchBase $extendedRightsDn -SearchScope OneLevel -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGuid)) {
        $name = [string]$right.name
        if ($wanted -contains $name) {
            $found[$name] = ([string]$right.rightsGuid).ToLowerInvariant()
        }
    }
    if ($found.Count -lt $wanted.Count) {
        # Rights that could not be read are a refusal and never a pass.
        throw 'the replication rights could not be read from this domain'
    }
    $sids = @($Sid) + @($GroupSids)
    $head = Get-ADObject -Identity $DomainDn -Properties nTSecurityDescriptor
    foreach ($rule in $head.nTSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
        if (-not $sids.Contains([string]$rule.IdentityReference.Value)) { continue }
        $objectType = ([string]$rule.ObjectType).ToLowerInvariant()
        if ($objectType -and ($found.Values -contains $objectType)) {
            throw 'newton-ops holds a right that replicates the directory; fix it before running this script again'
        }
        if ((-not $objectType) -and (($rule.ActiveRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0)) {
            throw 'newton-ops holds every extended right of the head of the domain; fix it before running this script again'
        }
    }
}

function Resolve-NewtonAccountSid([string]$Name) {
    # The SID of an account, by its name.  Windows PowerShell 5.1 only:
    # the translation of a name into a SID is a Windows behaviour, and
    # it is not supported by PowerShell on Linux.
    $account = New-Object System.Security.Principal.NTAccount($Name)
    return [string]$account.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function Test-BatchLogonRight([string]$RightsFile, [string]$Sid) {
    # True when the SID of the write account is one of the holders of
    # the SeBatchLogonRight, read from the export of secedit.  secedit
    # prints the NAME of an account and the SID of a well known one,
    # so every holder is resolved into a SID.  A line that is not
    # there is a refusal.
    if (-not (Test-Path -LiteralPath $RightsFile)) { return $false }
    $line = $null
    foreach ($text in @(Get-Content -LiteralPath $RightsFile)) {
        if ($text -match '^\\s*SeBatchLogonRight\\s*=\\s*(.*)$') { $line = $Matches[1]; break }
    }
    if ($null -eq $line) { return $false }
    foreach ($holder in ($line -split ',')) {
        $holder = $holder.Trim()
        if (-not $holder) { continue }
        if ($holder.StartsWith('*S-')) {
            if ($holder.Substring(1) -eq $Sid) { return $true }
            continue
        }
        try {
            $resolved = Resolve-NewtonAccountSid $holder
        } catch {
            continue
        }
        if ($resolved -eq $Sid) { return $true }
    }
    return $false
}

function Set-BatchLogonRightInTemplate([string]$Path, [string]$Sid) {
    # The SeBatchLogonRight of the template of a policy: the holders of
    # the right are kept and the SID of the write account is added to
    # them.  The template is UTF-16LE with a BOM and it stays that
    # way, so the policy of the domain is not broken by the edit.
    #
    # The file is read and written with the cmdlets of the file
    # system, so it may live on a share.
    $lines = $null
    try {
        $lines = @(Get-Content -LiteralPath $Path -Encoding Unicode -ErrorAction Stop)
    } catch {
        throw ('the template of the policy is missing or unreadable: ' + $Path)
    }
    $newLines = @()
    $inSection = $false
    $found = $false
    $changed = $false
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith('[')) {
            $inSection = ($trimmed -eq '[Privilege Rights]')
            $newLines += $line
            continue
        }
        if ($inSection -and ($trimmed -match '^(SeBatchLogonRight)\\s*=\\s*(.*)$')) {
            $found = $true
            $holders = @()
            foreach ($holder in ($Matches[2] -split ',')) {
                $holder = $holder.Trim()
                if ($holder) { $holders += $holder }
            }
            if ($holders -contains ('*' + $Sid)) {
                # The right is already there: the line is kept as it
                # is, and it is never written twice.
                $newLines += $line
            } else {
                $holders += ('*' + $Sid)
                $newLines += ('SeBatchLogonRight = ' + ($holders -join ','))
                $changed = $true
            }
            continue
        }
        $newLines += $line
    }
    if (-not $found) {
        # The line is not there at all: it is added to the section, and
        # the section is added when it is not there either.
        $sectionIndex = -1
        for ($index = 0; $index -lt $newLines.Count; $index++) {
            if ($newLines[$index].Trim() -eq '[Privilege Rights]') { $sectionIndex = $index }
        }
        if ($sectionIndex -lt 0) {
            $newLines += ''
            $newLines += '[Privilege Rights]'
            $newLines += ('SeBatchLogonRight = *' + $Sid)
        } else {
            $inserted = @()
            $inserted += $newLines[0..$sectionIndex]
            $inserted += ('SeBatchLogonRight = *' + $Sid)
            if ($sectionIndex -lt ($newLines.Count - 1)) { $inserted += $newLines[($sectionIndex + 1)..($newLines.Count - 1)] }
            $newLines = $inserted
        }
        $changed = $true
    }
    if ($changed) {
        Set-Content -LiteralPath $Path -Value $newLines -Encoding Unicode | Out-Null
    }
    return $changed
}

function Set-NewtonInstallAcl([string]$Path, [string]$OpsSid, [string]$OpsRights, [string]$Inheritance) {
    # The access control list of a path of the install.  The rules of
    # the path are explicit and the rules it inherits are gone: a
    # folder of ProgramData gives every local user a write, and the
    # helper refuses to answer when it finds one.  Windows PowerShell
    # 5.1 only: the access control list of the file system is a Windows
    # behaviour.
    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $opsSidObject = New-Object System.Security.Principal.SecurityIdentifier($OpsSid)
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $noInheritance = [System.Security.AccessControl.InheritanceFlags]::None
    $inherit = [System.Security.AccessControl.InheritanceFlags]$Inheritance
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    $acl.SetOwner($administrators)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $inherit, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inherit, $none, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, $OpsRights, $noInheritance, $none, $allow)))
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


_WIN_STEP_KEY = """
Write-Host 'Step 3: the approval key'

# The passphrase is asked here, on the domain controller, twice, and it
# is never echoed.  The secure string is marshalled once and the memory
# it came from is cleared right after.
$secure = Read-Host -AsSecureString -Prompt ('approval passphrase for ' + $DomainDevice)
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
# The approval key K is the key of the domain: it is derived with the
# name of the device that stands for the domain as its salt, the name
# the Newton host derived its own copy with, so every DC of the domain
# holds the same K (SPEC-1.4-REQUEST section 1).
$keyHex = Get-ApprovalKeyHex $passphrase $DomainDevice
$fingerprint = Get-ApprovalFingerprintHex $keyHex
$passphrase = $null
$passphraseAgain = $null

# The key is written with the access control list of SPEC-1.4 section
# 8: SYSTEM and Administrators have full control and the write account
# may read it.  The key itself is never printed.
New-Item -ItemType Directory -Path $AdDir -Force | Out-Null
[System.IO.File]::WriteAllText($ApprovalKeyPath, $keyHex + "`n", (New-Object System.Text.UTF8Encoding($false)))
$keyHex = $null
$administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$opsSidObject = New-Object System.Security.Principal.SecurityIdentifier($opsSid)
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
$keyAcl = Get-Acl -LiteralPath $ApprovalKeyPath
$keyAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($keyAcl.Access)) { [void]$keyAcl.RemoveAccessRule($rule) }
$keyAcl.SetOwner($administrators)
$keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $none, $none, $allow)))
$keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $none, $none, $allow)))
$keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, 'Read', $none, $none, $allow)))
Set-Acl -LiteralPath $ApprovalKeyPath -AclObject $keyAcl
Write-Host ('The approval key is installed. Its fingerprint is ' + $fingerprint)
Write-Host 'Compare that fingerprint with the one the Newton host printed.'
"""


_WIN_STEP_FILES = """
Write-Host 'Step 4: the files'

New-Item -ItemType Directory -Path $AdDir -Force | Out-Null

# The access control list of the install root: the rules are explicit
# and the rules the folder inherits from ProgramData are gone.  A local
# user may not write beside the helper.
Set-NewtonInstallAcl $AdDir $opsSid 'ReadAndExecute' 'ContainerInherit, ObjectInherit'

@@HELPER@@
[System.IO.File]::WriteAllBytes($HelperPath, [System.Convert]::FromBase64String($helperB64))
$helperHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $HelperPath).Hash.ToLowerInvariant()
if ($helperHash -ne '@@HELPER_HASH@@') {
    throw 'the sha256 of write.ps1 does not match the package'
}
Write-Host ('sha256 write.ps1 ' + $helperHash)

# The device name the helper of this controller answers to: the name of
# the device that stands for the domain, the same on every controller
# of the domain.  A request names the domain, and the helper refuses
# with `schema` when the name differs from this one.
[System.IO.File]::WriteAllText($DeviceFilePath, $DomainDevice + "`n", (New-Object System.Text.UTF8Encoding($false)))
Set-NewtonInstallAcl $DeviceFilePath $opsSid 'Read' 'None'

# The access control list of the helper: the rules of the collector.
$administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$opsSidObject = New-Object System.Security.Principal.SecurityIdentifier($opsSid)
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
$children = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$helperAcl = Get-Acl -LiteralPath $HelperPath
$helperAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($helperAcl.Access)) { [void]$helperAcl.RemoveAccessRule($rule) }
$helperAcl.SetOwner($administrators)
$helperAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $none, $none, $allow)))
$helperAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $none, $none, $allow)))
$helperAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, 'ReadAndExecute', $none, $none, $allow)))
Set-Acl -LiteralPath $HelperPath -AclObject $helperAcl

# The transaction store: SYSTEM and Administrators have full control
# and the write account may read it, create files in it and write them.
# It may not delete anything.
New-Item -ItemType Directory -Path $TxDir -Force | Out-Null
$txRights = [System.Security.AccessControl.FileSystemRights]'Read, CreateFiles, WriteData'
$txAcl = Get-Acl -LiteralPath $TxDir
$txAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($txAcl.Access)) { [void]$txAcl.RemoveAccessRule($rule) }
$txAcl.SetOwner($administrators)
$txAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $children, $none, $allow)))
$txAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $children, $none, $allow)))
$txAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, $txRights, $children, $none, $allow)))
Set-Acl -LiteralPath $TxDir -AclObject $txAcl
Write-Host 'The helper, the device name and the transaction store are in place.'
"""


_WIN_STEP_LOGIN = """
Write-Host 'Step 5: the login'

# The authorized key of the write path, with the access control list
# of the measured one: SYSTEM and Administrators have full control and
# the write account may read and execute it.
[System.IO.File]::WriteAllText($AuthorizedKeysPath, 'restrict @@KEYLINE@@' + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
$administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$opsSidObject = New-Object System.Security.Principal.SecurityIdentifier($opsSid)
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
$keysAcl = Get-Acl -LiteralPath $AuthorizedKeysPath
$keysAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($keysAcl.Access)) { [void]$keysAcl.RemoveAccessRule($rule) }
$keysAcl.SetOwner($administrators)
$keysAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, 'FullControl', $none, $none, $allow)))
$keysAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $none, $none, $allow)))
$keysAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($opsSidObject, 'ReadAndExecute', $none, $none, $allow)))
Set-Acl -LiteralPath $AuthorizedKeysPath -AclObject $keysAcl

# sshd accepts the key only for the builtin OpenSSH Users group, so the
# account joins it.  The group is not privileged.
$openSshUsers = Get-ADGroup -Identity ('CN=OpenSSH Users,CN=Builtin,' + (Get-ADDomain).DistinguishedName)
$isMember = $false
foreach ($member in @(Get-ADGroupMember -Identity $openSshUsers -ErrorAction SilentlyContinue)) {
    $memberName = $member.PSObject.Properties['SamAccountName']
    if (($null -ne $memberName) -and ([string]$memberName.Value -eq $OpsName)) { $isMember = $true }
}
if (-not $isMember) {
    Add-ADGroupMember -Identity $openSshUsers -Members $OpsName
    Write-Host 'newton-ops is now a member of the domain-local OpenSSH Users group.'
} else {
    Write-Host 'newton-ops is already a member of the domain-local OpenSSH Users group.'
}

# The sshd block of the write path.  The configuration is backed up
# once and it is put back when sshd refuses it.
if (-not (Test-Path -LiteralPath $SshdConfig)) { throw 'the sshd configuration is missing' }
if (-not (Test-Path -LiteralPath $SshdBackup)) {
    Copy-Item -LiteralPath $SshdConfig -Destination $SshdBackup -Force
    Write-Host 'The sshd configuration is backed up once, as .bak-newton-write.'
}
$config = Get-Content -LiteralPath $SshdConfig -Raw
$sshdChanged = $false
if ($config -notlike ('*' + $BlockMarker + '*')) {
    $netbios = ([string](Get-ADDomain).NetBIOSName).ToLowerInvariant()
    $blockLines = @(
        $BlockMarker
        ("Match User $($netbios)\\$OpsName")
        '    AuthorizedKeysFile __PROGRAMDATA__/Newton/ad/write_authorized_keys'
        '    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\ProgramData\\Newton\\ad\\write.ps1'
        '    PermitTTY no'
        '    AllowTcpForwarding no'
        '    PermitTunnel no'
        '    X11Forwarding no'
        '    AllowAgentForwarding no'
    )
    $block = ($blockLines -join "`n") + "`n"
    if (-not $config.EndsWith("`n")) { $block = "`n" + $block }
    [System.IO.File]::WriteAllText($SshdConfig, $config + $block, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $true
    Write-Host 'The write block is in the sshd configuration.'
} else {
    Write-Host 'The write block is already in the sshd configuration.'
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
$sshdSaid = ''
try {
    # The output of sshd is captured: it is printed only when the
    # configuration was refused, because that is the one time the owner
    # has to read it.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $sshdOut = & $sshdExe -t 2>&1
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    $sshdExit = $LASTEXITCODE
    $sshdSaid = (($sshdOut | ForEach-Object { [string]$_ }) -join ' ')
} catch {
    $sshdExit = 1
}
if ($sshdExit -ne 0) {
    [System.IO.File]::WriteAllText($SshdConfig, $config, (New-Object System.Text.UTF8Encoding($false)))
    $sshdChanged = $false
    if ($sshdSaid) {
        Write-Host ('sshd said: ' + $sshdSaid)
    }
    throw 'sshd refused the configuration. The configuration was put back.'
}
Write-Host 'sshd accepted the configuration.'
"""


_WIN_STEP_BATCH_LOGON = """
Write-Host 'Step 6: the SeBatchLogonRight'

# The undo task runs as the write account with a S4U token, and it runs
# only when the account holds the SeBatchLogonRight.  The right is
# granted on the PDC only, through the Default Domain Controllers
# Policy, and the holders of the right are kept.
if ($isPdc) {
    # The backup of the policy was made by the step 0, before any
    # change: a run that could not make it stopped there.  The step 6
    # uses that backup and takes no other one.
    Write-Host ('The Default Domain Controllers Policy is backed up in ' + $backupDir)

    # The read of the policy is made on the PDC: the share of the name
    # of the domain may be served by another controller, and the policy
    # of the PDC is not there.
    $gpo = Get-GPO -Guid $DefaultDcPolicyGuid -Server $PdcServer -ErrorAction Stop
    if (-not $gpo) {
        throw 'the Default Domain Controllers Policy was not found on the PDC'
    }

    # The policy object is read by its own name: it is the object
    # CN={<guid>},CN=Policies,CN=System,<domain>, and it holds the path
    # of the folder of the policy.
    $gpoObject = Get-ADObject -Identity ('CN={' + $DefaultDcPolicyGuid + '},CN=Policies,CN=System,' + $DomainDn) -Properties versionNumber, gPCFileSysPath
    if (-not $gpoObject) {
        throw 'the Default Domain Controllers Policy was not found'
    }
    $gpoDir = [string]$gpoObject.gPCFileSysPath
    if (-not $gpoDir) {
        throw 'the Default Domain Controllers Policy has no path'
    }
    # The path the directory answers is only read to prove that the
    # policy is the one of its own GUID.  It is never the path that is
    # written: the files are edited in the share of the SYSVOL of the
    # PDC, because the share of the name of the domain may be served by
    # another controller.
    $wantedPolicyTail = '\\Policies\\{' + $DefaultDcPolicyGuid + '}'
    if (-not $gpoDir.EndsWith($wantedPolicyTail, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('the path of the Default Domain Controllers Policy does not end with ' + $wantedPolicyTail)
    }

    # The template of the policy is in the folder of the policy of the
    # PDC, and not in the folder of the policies.
    $changed = Set-BatchLogonRightInTemplate $GptTmplPath $opsSid
    if ($changed) {
        Write-Host 'The SeBatchLogonRight of the policy holds newton-ops now, and it holds everyone it held before.'

        # The machine version of the policy goes up in the folder of the
        # policy and in the GPO object, so the controllers take the new
        # template.
        $gptIni = $GptIniPath
        if (Test-Path -LiteralPath $gptIni) {
            $iniLines = @(Get-Content -LiteralPath $gptIni -ErrorAction Stop)
            $newIni = @()
            foreach ($line in $iniLines) {
                if ($line.Trim() -like 'Version=*') {
                    $old = [int](($line -split '=', 2)[1])
                    $newIni += ('Version=' + ($old + 1))
                } else {
                    $newIni += $line
                }
            }
            Set-Content -LiteralPath $gptIni -Value $newIni -Encoding Ascii | Out-Null
        }
        $newVersion = [int]$gpoObject.versionNumber + 1
        Set-ADObject -Identity $gpoObject.DistinguishedName -Replace @{ versionNumber = $newVersion }
        Write-Host ('The machine version of the policy is ' + $newVersion + ' now.')
    } else {
        Write-Host 'The SeBatchLogonRight of the policy holds newton-ops already.'
    }
} else {
    Write-Host 'The SeBatchLogonRight is granted on the PDC only.'
}

gpupdate /target:computer /force | Out-Null
$rightsFile = Join-Path $env:TEMP 'newton-user-rights.txt'
if (Test-Path -LiteralPath $rightsFile) { Remove-Item -LiteralPath $rightsFile -Force }
secedit /export /areas USER_RIGHTS /cfg $rightsFile /quiet | Out-Null
if (-not (Test-Path -LiteralPath $rightsFile)) {
    throw 'the export of secedit failed: the SeBatchLogonRight of newton-ops could not be proved'
}
# The right is proved: the SID of the write account has to be one of
# the holders of the right on this controller.  The export is read by
# the check itself, and the verify prints ONE line: the match object of
# Select-String is not printed, the owner reads the report and nothing
# else.
if (-not (Test-BatchLogonRight $rightsFile $opsSid)) {
    Remove-Item -LiteralPath $rightsFile -Force
    throw 'the SeBatchLogonRight of newton-ops could not be proved on this controller'
}
Remove-Item -LiteralPath $rightsFile -Force
Write-Host 'SeBatchLogonRight holds newton-ops (verified by secedit)'
"""


_WIN_STEP_INVENTORY = """
Write-Host 'Step 7: the inventory entry'
Write-Host ''
Write-Host ('[devices.' + $Device + ']')
Write-Host 'platform = "ad-windows-write"'
Write-Host ('ad_domain = "' + $DomainDevice + '"')
Write-Host ('ad_domain_guid = "' + $DomainHeadGuid + '"')
Write-Host ('host = "' + $WriteHost + '"')
Write-Host ('user = "newton-ops@' + $Domain + '"')
Write-Host 'key_file = "<the private key of the write key, on the Newton host>"'
Write-Host 'known_hosts = "<the pinned known_hosts of the controller>"'
Write-Host ('domain = "' + $Domain + '"')
Write-Host ''
Write-Host ('The installed public key (sha256): @@KEYSHA@@')
Write-Host ('The key of this controller is ' + $AuthorizedKeysPath)
Write-Host 'The ad_domain of the entry is the inventory name of the device that stands for the domain: the PDC emulator''s own entry. On every other DC, run the setup with --domain-device <that name>.'
Write-Host 'The key_file and known_hosts lines of the entry are placeholders the owner fills in.'
"""


_WIN_STEP_RESTART = """
Write-Host 'Step 8: the sshd restart'
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


# ---- the Samba script -------------------------------------------------------


def samba_write_script(
    *,
    domain: str,
    pubkey: str,
    device: str,
    host: str,
    ous: Sequence[str],
    domain_device: str | None = None,
) -> str:
    """The bash script that sets one Samba write host up.

    The public key is validated again here, so a caller that did not
    use ``validate_public_key`` cannot put a second field or an option
    into the script.  ``domain_device`` is the inventory name of the
    device that stands for the domain; without it the entry names the
    device of ``device``.
    """
    if DOMAIN_RE.fullmatch(domain) is None:
        raise SetupError("the domain must be a DNS name")
    if HOST_RE.fullmatch(host) is None:
        raise SetupError("the host must be a host name or an IP address")
    if DEVICE_RE.fullmatch(device) is None:
        raise SetupError("the device name must be [a-z][a-z0-9-]{0,31}")
    if domain_device is None:
        domain_device = device
    if DEVICE_RE.fullmatch(domain_device) is None:
        raise SetupError(
            "the domain device name must be [a-z][a-z0-9-]{0,31}"
        )
    pubkey = validate_public_key(pubkey)
    ous = validate_ous(ous, domain)
    helper = _read_helper(SAMBA_WRITE_HELPER_PATH)

    parts = [
        _SAMBA_HEADER.replace("@@DOMAIN@@", domain)
        .replace("@@DEVICE@@", device)
        .replace("@@DOMAIN_DEVICE@@", domain_device)
        .replace("@@HOST@@", host)
        .replace("@@DOMAIN_DN@@", domain_dn(domain))
        .replace("@@KEYLINE@@", pubkey)
        .replace("@@OUS@@", _samba_ous_block(ous)),
        _SAMBA_FUNCTIONS,
        _SAMBA_STEP_PRECHECKS,
        _SAMBA_STEP_ACCOUNT,
        _SAMBA_STEP_DELEGATION,
        _SAMBA_STEP_KEY,
        _SAMBA_STEP_FILES.replace(
            "@@HELPER@@", _b64_block(helper)
        ).replace("@@HELPER_HASH@@", _sha256(helper)),
        _SAMBA_STEP_KEYTAB,
        _SAMBA_STEP_LOGIN.replace("@@KEYLINE@@", pubkey),
        _SAMBA_STEP_INVENTORY.replace("@@DEVICE@@", device)
        .replace("@@DOMAIN_DEVICE@@", domain_device)
        .replace("@@HOST@@", host)
        .replace("@@DOMAIN@@", domain)
        .replace("@@KEYSHA@@", _sha256(pubkey.encode("utf-8"))),
    ]
    return "\n".join(parts)


def _samba_ous_block(ous: Sequence[str]) -> str:
    """The bash array of the delegated locations."""
    return "\n".join(f"    '{ou}'" for ou in ous)


_SAMBA_HEADER = """\
#!/usr/bin/env bash
# Newton's Active Directory write setup (Samba).
# Device: @@DEVICE@@   Host: @@HOST@@   Domain: @@DOMAIN@@
#
# Read this script, then run it as root on the Samba domain
# controller.  Every step is idempotent: running it a second time
# changes nothing the second time.
#
# The pre-checks come first and they change nothing.  A run that stops
# in them leaves the domain as it was.
#
# The delegation runs on the PDC only: the other domain controllers
# replicate it, so a run on another controller changes nothing there.
#
# The sudoers line is the last thing the script writes: a run that
# stops before it leaves no sudoers line behind, so a host that is not
# ready never lets the account run the write helper.
set -euo pipefail

DOMAIN='@@DOMAIN@@'
DEVICE='@@DEVICE@@'
DOMAIN_DEVICE='@@DOMAIN_DEVICE@@'
WRITE_HOST='@@HOST@@'
OPS_NAME='newton-ops'
LOGIN_NAME='newton-ops-ssh'
DOMAIN_DN='@@DOMAIN_DN@@'
SCHEMA_DN="CN=Schema,CN=Configuration,${DOMAIN_DN}"
DELEGATED_OUS=(
@@OUS@@
)
SAMBA_LDB='/var/lib/samba/private/sam.ldb'
CONFIG_DIR='/etc/newton-ad'
HELPER_PATH='/usr/local/sbin/newton-ad-samba-write'
APPROVAL_KEY_PATH='/etc/newton-ad/approval.key'
DEVICE_FILE='/etc/newton-ad/device.txt'
KEYTAB_PATH='/etc/newton-ad/ops.keytab'
TX_DIR='/var/lib/newton-ad/tx'
HOME_DIR='/var/lib/newton-ops-ssh'
KEYFILE='/var/lib/newton-ops-ssh/.ssh/authorized_keys'
SUDOERS_FILE='/etc/sudoers.d/newton-ops-ssh'
SUDOERS_LINE='newton-ops-ssh ALL=(root) NOPASSWD: /usr/local/sbin/newton-ad-samba-write ""'
KEY_LINE='restrict,command="sudo -n /usr/local/sbin/newton-ad-samba-write" @@KEYLINE@@'
WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT
"""


_SAMBA_FUNCTIONS = """
# The helpers of this script.

ldif_value() {
    # $1 the attribute.  The LDIF is unfolded first: a line that starts
    # with a space continues the line before it, so a long value is one
    # value and not two lines.  Every value of the attribute is
    # printed, one per line.
    local attr="$1"
    local line=""
    local value=""
    local have=0
    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in
            " "*)
                # A continuation of the value that is being read.
                if [ "${have}" = "1" ]; then
                    value="${value}${line# }"
                fi
                ;;
            *)
                if [ "${have}" = "1" ]; then
                    printf '%s\\n' "${value}"
                fi
                value=""
                have=0
                case "${line}" in
                    "${attr}: "*) value="${line#*: }"; have=1 ;;
                    "${attr}:"*) value="${line#*:}"; have=1 ;;
                esac
                ;;
        esac
    done
    if [ "${have}" = "1" ]; then
        printf '%s\\n' "${value}"
    fi
}

is_privileged_sid() {
    # The privileged set of SPEC-1.4 section 5: the relative
    # identifiers of the privileged groups of any domain of the forest,
    # and the privileged groups of the builtin domain.  The tokenGroups
    # of an account are transitive, so a group that is nested in a
    # privileged group is in the list too.
    case "$1" in
        S-1-5-32-544|S-1-5-32-548|S-1-5-32-549|S-1-5-32-550|S-1-5-32-551|S-1-5-32-552) return 0 ;;
    esac
    case "$1" in
        S-1-5-21-*-*) ;;
        *) return 1 ;;
    esac
    local rid="${1##*-}"
    case "${rid}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    case " 498 512 516 518 519 520 521 525 526 527 " in
        *" ${rid} "*) return 0 ;;
    esac
    return 1
}

install_blob() {
    # $1 the file of the package, $2 the path to install it at, $3 the
    # mode, $4 the sha256 of the package file.  A file that is already
    # the file of the package is left alone, unless its mode or its
    # owner is wrong: then it is installed again, which repairs it.
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

# The two programs of this script.  They are written here, in the work
# directory of the run, and they are removed with it.
cat > "${WORK_DIR}/approval.py" <<'NEWTON_AD_PY_EOF'
'''The approval key of this controller.

The passphrase is asked here, twice, and it is never echoed.  The key is
derived from it and it is written with mode 0600: the key itself is
never shown, only its fingerprint.
'''

import getpass
import hashlib
import hmac
import os
import sys


def derive(passphrase, device):
    '''The approval key K.

    K = PBKDF2-HMAC-SHA256(passphrase, "newton-approve-v1:" + device,
    600000, 32).  It is the same key the Newton host derives with
    derive_k.
    '''
    salt = ("newton-approve-v1:" + device).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 600000, 32)


def fingerprint(key):
    '''The fingerprint of the key: HMAC-SHA256 of the constant message.'''
    return hmac.new(key, b"newton-approval-fingerprint-v1", hashlib.sha256).hexdigest()


def main(argv):
    device = argv[1]
    path = argv[2]
    first = getpass.getpass("approval passphrase for %s: " % device)
    second = getpass.getpass("approval passphrase again: ")
    if not first:
        sys.stderr.write("the approval passphrase must not be empty\\n")
        return 1
    if first != second:
        sys.stderr.write("the two approval passphrases do not match\\n")
        return 1
    key = derive(first, device)
    del first, second
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(key.hex() + "\\n")
    os.chmod(path, 0o600)
    print(fingerprint(key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
NEWTON_AD_PY_EOF

cat > "${WORK_DIR}/ad_write_setup.py" <<'NEWTON_AD_PY_EOF'
'''The delegation of the write path and the check of the replication rights.

The GUIDs of the classes and of the attributes are read from the schema
of the domain at the moment this program runs.  No GUID of a schema
object is typed here, and every command is run with an argument list.
'''

import subprocess
import sys


PROPERTIES = (
    ("userAccountControl", "user"),
    ("msDS-SupportedEncryptionTypes", "user"),
    ("lockoutTime", "user"),
    ("name", "user"),
    ("cn", "user"),
    ("userAccountControl", "computer"),
    ("msDS-SupportedEncryptionTypes", "computer"),
    ("name", "computer"),
    ("cn", "computer"),
    ("member", "group"),
)

CHILDREN = (
    ("create", "user"),
    ("delete", "user"),
    ("create", "computer"),
    ("delete", "computer"),
)

HEAD_PROPERTY = "ms-DS-MachineAccountQuota"

CREATE_CHILD = 0x00000001
DELETE_CHILD = 0x00000002
WRITE_PROPERTY = 0x00000020

REPLICATION_RIGHTS = (
    "DS-Replication-Get-Changes",
    "DS-Replication-Get-Changes-All",
    "DS-Replication-Get-Changes-In-Filtered-Set",
)


def run(argv):
    '''Run one command with an argument list.'''
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def schema_guid(schema_dn, ldb, filter_text):
    '''The schemaIDGUID of the object the filter names.

    The attribute is schemaIDGUID: the name of the attribute is read
    as it comes, and the line that holds it is found without the case.
    '''
    result = run(["ldbsearch", "-H", ldb, "-b", schema_dn, filter_text, "schemaIDGUID"])
    for line in result.stdout.splitlines():
        if line.lower().startswith("schemaidguid:"):
            return line.split(":", 1)[1].strip()
    return ""


def class_guid(schema_dn, ldb, name):
    '''The schemaIDGUID of a class of the schema.

    The class is named by its display name: the name attribute of a
    class of the schema holds the CN of the object, not the name the
    delegation uses.
    '''
    return schema_guid(schema_dn, ldb, "(lDAPDisplayName=%s)" % name)


def attribute_guid(schema_dn, ldb, name):
    '''The schemaIDGUID of an attribute of the schema.

    The attribute is named by its display name too.
    '''
    return schema_guid(schema_dn, ldb, "(lDAPDisplayName=%s)" % name)


def security_module():
    '''The security module of Samba, which parses the descriptors.'''
    from samba.dcerpc import security

    return security


def domain_sid_of(sid):
    '''The SID of the domain of an account SID.

    The SID of the domain is the SID of the account without its last
    component: it is the SID the well known names of a descriptor are
    resolved against.
    '''
    if "-" not in sid:
        return sid
    return sid.rsplit("-", 1)[0]


def descriptor_aces(sddl, domain_sid):
    '''The ACEs of a security descriptor, as Samba parses them.

    The descriptor is parsed with the parser of Samba and the ACEs are
    compared field by field.  A descriptor prints its access masks as
    letters and its well known SIDs as names, so a comparison of the
    text never matches what is stored.

    A descriptor that the parser of Samba refuses stops the script with
    the exit code 2: a check that could not be made is never a pass.
    '''
    if not sddl.strip():
        return []
    security = security_module()
    try:
        descriptor = security.descriptor.from_sddl(
            sddl, security.dom_sid(domain_sid)
        )
    except Exception as exc:
        sys.stderr.write("the security descriptor could not be read: %s\\n" % exc)
        raise SystemExit(2)
    if descriptor.dacl is None:
        return []
    return list(descriptor.dacl.aces)


def ace_fields(ace):
    '''The fields of one ACE, as the comparison uses them.

    The type, the flags, the access mask, the object type, the
    inherited object type and the trustee.

    The module of Samba has no name of its own for the two flags of
    the object of an ACE: they are the measured constants
    SEC_ACE_OBJECT_TYPE_PRESENT and
    SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT.
    '''
    security = security_module()
    object_type = ""
    inherited_type = ""
    holder = getattr(ace, "object", None)
    if holder is not None:
        flags = getattr(holder, "flags", 0)
        if flags & security.SEC_ACE_OBJECT_TYPE_PRESENT:
            object_type = str(holder.type).lower()
        if flags & security.SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT:
            inherited_type = str(holder.inherited_type).lower()
    return (
        ace.type,
        ace.flags,
        ace.access_mask,
        object_type,
        inherited_type,
        str(ace.trustee).lower(),
    )


def trustee_of(wanted):
    '''The SID of the principal of an ACE.

    An ACE of the SDDL has six fields: the type, the flags, the rights,
    the object GUID, the inherited object GUID and the trustee.  The
    trustee is the sixth field.
    '''
    fields = wanted.strip().strip("()").split(";")
    if len(fields) < 6:
        return ""
    return fields[5].strip()


def wanted_fields(wanted, domain_sid):
    '''The fields of the ACE that is wanted.'''
    text = wanted.strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    aces = descriptor_aces("O:SYG:SYD:(" + text + ")", domain_sid)
    if not aces:
        sys.stderr.write("the ACE that is wanted could not be read\\n")
        raise SystemExit(1)
    return ace_fields(aces[0])


def same_ace(stored, wanted):
    '''True when a stored ACE grants the same thing to the same principal.

    The wanted fields are the ones of the ACE that was asked for, and
    they are compared with the fields of the stored ACE: the type, the
    flags, the access mask, the object type, the inherited object type
    and the trustee.
    '''
    return ace_fields(stored) == wanted


def current_sddl(dn):
    '''The security descriptor of an object, as the SDDL text.

    samba-tool dsacl get prints a line that names the object and then
    the descriptor: only the descriptor is read.
    '''
    result = run(["samba-tool", "dsacl", "get", "--objectdn", dn])
    if result.returncode != 0:
        sys.stderr.write("samba-tool dsacl get failed on %s\\n" % dn)
        raise SystemExit(1)
    for line in result.stdout.splitlines():
        if line.startswith("O:"):
            return line.strip()
    return ""


def ace(sid, mask, object_type, inherited, flags):
    '''One ACE of the delegation, in the SDDL of the directory.

    An ACE of the SDDL has six fields: the type, the flags, the rights,
    the object GUID, the inherited object GUID and the trustee.  Samba
    refuses an ACE with a seventh field.

    An ACE that names an object type or an inherited object type is an
    object ACE.  Samba accepts an ACE of type A that carries the GUIDs,
    keeps the right and drops the GUIDs, and the right is then a write
    on every property of every object below.
    '''
    kind = "OA" if (object_type or inherited) else "A"
    fields = [kind, flags, "0x%08x" % mask, object_type, inherited, sid]
    return "(" + ";".join(fields) + ")"


def grant(sddl, dn, wanted, label):
    '''Add one ACE to a descriptor, when it is missing.

    The ACE that is wanted is given to samba-tool alone: it adds the
    ACEs it is given and keeps the descriptor it finds.  The descriptor
    is read back afterwards, and a grant that came back wider than the
    one that was asked for stops the script.
    '''
    domain_sid = domain_sid_of(trustee_of(wanted))
    fields = wanted_fields(wanted, domain_sid)
    for stored in descriptor_aces(sddl, domain_sid):
        if same_ace(stored, fields):
            print("  %s of %s is present" % (label, dn))
            return sddl
    result = run(["samba-tool", "dsacl", "set", "--objectdn", dn, "--sddl", wanted])
    if result.returncode != 0:
        sys.stderr.write("samba-tool dsacl set refused the ACE on %s\\n" % dn)
        raise SystemExit(1)
    after = current_sddl(dn)
    for stored in descriptor_aces(after, domain_sid):
        if same_ace(stored, fields):
            print("  %s of %s is added" % (label, dn))
            return after
    sys.stderr.write(
        "samba-tool dsacl set did not store the requested ACE on %s\\n" % dn
    )
    raise SystemExit(1)


def delegate(ous, domain_dn, schema_dn, ldb, sid):
    '''The delegation of SPEC-1.4 section 8.'''
    classes = {}
    for name in ("user", "computer", "group"):
        guid = class_guid(schema_dn, ldb, name)
        if not guid:
            sys.stderr.write("the schema of this domain holds no class %s\\n" % name)
            raise SystemExit(1)
        classes[name] = guid
    attributes = {}
    for attribute, _klass in PROPERTIES:
        if attribute in attributes:
            continue
        guid = attribute_guid(schema_dn, ldb, attribute)
        if not guid:
            sys.stderr.write("the schema of this domain holds no attribute %s\\n" % attribute)
            raise SystemExit(1)
        attributes[attribute] = guid
    for dn in ous:
        sddl = current_sddl(dn)
        for attribute, klass in PROPERTIES:
            wanted = ace(sid, WRITE_PROPERTY, attributes[attribute], classes[klass], "OICI")
            sddl = grant(sddl, dn, wanted, "write %s on %s" % (attribute, klass))
        for right, klass in CHILDREN:
            mask = CREATE_CHILD if right == "create" else DELETE_CHILD
            wanted = ace(sid, mask, classes[klass], "", "OICI")
            sddl = grant(sddl, dn, wanted, "%s child %s" % (right, klass))
    head_guid = attribute_guid(schema_dn, ldb, HEAD_PROPERTY)
    if not head_guid:
        sys.stderr.write("the schema of this domain holds no attribute %s\\n" % HEAD_PROPERTY)
        raise SystemExit(1)
    sddl = current_sddl(domain_dn)
    wanted = ace(sid, WRITE_PROPERTY, head_guid, "", "")
    grant(sddl, domain_dn, wanted, "write %s" % HEAD_PROPERTY)


def replication_rights(domain_dn, ldb):
    '''The GUIDs of the rights that replicate the directory.

    The rights that replicate are controlAccessRight objects under
    CN=Extended-Rights,CN=Configuration of this domain: they are not
    objects of the schema, and a search of the schema finds nothing.
    '''
    names = "".join("(name=%s)" % name for name in REPLICATION_RIGHTS)
    base = "CN=Extended-Rights,CN=Configuration," + domain_dn
    result = run([
        "ldbsearch",
        "-H",
        ldb,
        "-b",
        base,
        "(&(objectClass=controlAccessRight)(|%s))" % names,
        "rightsGuid",
    ])
    found = {}
    for record in result.stdout.split("\\n\\n"):
        name = ""
        guid = ""
        for line in record.splitlines():
            lowered = line.lower()
            if lowered.startswith("dn:"):
                name = line.split(":", 1)[1].strip()
            elif lowered.startswith("rightsguid:"):
                guid = line.split(":", 1)[1].strip().lower()
        if not guid:
            continue
        rdn = name.split(",")[0].strip()
        if rdn.lower().startswith("cn="):
            rdn = rdn[3:]
        for wanted in REPLICATION_RIGHTS:
            if rdn.lower() == wanted.lower():
                found[wanted] = guid
    return found


def rights(domain_dn, schema_dn, ldb, sid, group_sids):
    '''Refuse when the account holds a right that replicates the directory.

    The rights that replicate are read from the extended rights of this
    domain: no GUID is typed here.  Rights that could not be read are a
    refusal and never a pass.

    The exit code tells the two refusals apart: 1 is an account that
    holds a right that replicates the directory, and 2 is a check that
    could not be made.  The script prints the line of the case.
    '''
    try:
        security = security_module()
        replication = replication_rights(domain_dn, ldb)
        if len(replication) < len(REPLICATION_RIGHTS):
            sys.stderr.write(
                "the replication rights could not be read from this domain\\n"
            )
            return 2
        sids = set([sid.lower()])
        for group in group_sids:
            sids.add(group.lower())
        domain_sid = domain_sid_of(sid)
        for stored in descriptor_aces(current_sddl(domain_dn), domain_sid):
            fields = ace_fields(stored)
            if fields[5] not in sids:
                continue
            object_type = fields[3]
            if object_type and object_type in replication.values():
                sys.stderr.write(
                    "newton-ops holds a right that replicates the directory\\n"
                )
                return 1
            if not object_type and (fields[2] & security.SEC_ADS_CONTROL_ACCESS):
                sys.stderr.write(
                    "newton-ops holds every extended right of the head of the "
                    "domain\\n"
                )
                return 1
    except Exception as exc:
        # A check that could not be made is a refusal and never a pass.
        sys.stderr.write(
            "the replication rights could not be checked: %s\\n" % exc
        )
        return 2
    return 0


def main(argv):
    mode = argv[1]
    if mode == "delegate":
        ous = [one for one in argv[2].split("|") if one]
        delegate(ous, argv[3], argv[4], argv[5], argv[6])
        return 0
    if mode == "rights":
        return rights(argv[2], argv[3], argv[4], argv[5], argv[6:])
    sys.stderr.write("unknown mode\\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
NEWTON_AD_PY_EOF
"""


_SAMBA_STEP_PRECHECKS = """
echo "Step 0: the pre-checks"

if [ "$(id -u)" != "0" ]; then
    echo "this script must run as root" >&2
    exit 1
fi

REALM="$(samba-tool testparm --parameter-name=realm --suppress-prompt 2>/dev/null | head -n 1 | tr -d '[:space:]' || true)"
if [ -z "${REALM}" ]; then
    # The realm was not read by testparm: the Domain line of
    # samba-tool domain info names the same domain.
    REALM="$(samba-tool domain info 127.0.0.1 2>/dev/null | sed -n 's/^Domain *: *//p' | head -n 1 | tr -d '[:space:]' || true)"
fi
if [ -z "${REALM}" ]; then
    echo "samba-tool testparm did not name the realm of this controller" >&2
    exit 1
fi
if [ "$(printf '%s' "${REALM}" | tr 'a-z' 'A-Z')" != "$(printf '%s' "${DOMAIN}" | tr 'a-z' 'A-Z')" ]; then
    echo "this controller is a domain controller of ${REALM}, not of ${DOMAIN}" >&2
    exit 1
fi

for ou in "${DELEGATED_OUS[@]}"; do
    if ! ldbsearch -H "${SAMBA_LDB}" -b "${ou}" --scope=base '(objectClass=*)' dn 2>/dev/null | grep -q '^dn:'; then
        echo "the delegated location does not exist: ${ou}" >&2
        exit 1
    fi
done

# The rootDSE is read with an empty base: the filter is the search
# filter, and the base of the rootDSE is the empty string.
DS_SERVICE_NAME="$(ldbsearch -H "${SAMBA_LDB}" -b '' --scope=base '(objectClass=*)' dsServiceName 2>/dev/null | ldif_value dsServiceName || true)"
FSMO_ROLE_OWNER="$(ldbsearch -H "${SAMBA_LDB}" -b "${DOMAIN_DN}" --scope=base '(objectClass=domainDNS)' fSMORoleOwner 2>/dev/null | ldif_value fSMORoleOwner || true)"
if [ -z "${DS_SERVICE_NAME}" ] || [ -z "${FSMO_ROLE_OWNER}" ]; then
    echo "the role owner of the domain could not be read" >&2
    exit 1
fi
# The objectGUID of the head of the domain, read with the same base
# search that read the role owner.  The inventory entry of this
# controller carries it: the maq verb targets the head of the domain by
# that guid alone.  The value is carried in the form the loader takes,
# lower case hex, whatever the case of the answer of the directory.
DOMAIN_GUID="$(ldbsearch -H "${SAMBA_LDB}" -b "${DOMAIN_DN}" --scope=base '(objectClass=domainDNS)' objectGUID 2>/dev/null | ldif_value objectGUID | tr 'A-F' 'a-f' || true)"
if ! printf '%s' "${DOMAIN_GUID}" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
    echo "the objectGUID of the head of the domain is not a guid" >&2
    exit 1
fi
if [ "$(printf '%s' "${DS_SERVICE_NAME}" | tr 'a-z' 'A-Z')" = "$(printf '%s' "${FSMO_ROLE_OWNER}" | tr 'a-z' 'A-Z')" ]; then
    IS_PDC=yes
    echo "This host holds the PDC emulator role of the domain."
else
    IS_PDC=no
    echo "This host does not hold the PDC emulator role of the domain."
fi
# An entry that names its own device stands for the domain, and the
# domain has one device that stands for it: when another DC of the
# domain has an entry too, the loader of the inventory refuses the
# inventory and every change of the domain is refused.  The warning
# says so; the run goes on, because a domain device may be a
# controller that does not hold the role.
if [ "${IS_PDC}" = "no" ] && [ "${DOMAIN_DEVICE}" = "${DEVICE}" ]; then echo "WARNING: this DC does not hold the PDC emulator role and its entry names its own device. If another DC of the domain already has a write entry, run this setup again with --domain-device <that entry's name>, or every change of the domain is refused."; fi
"""


_SAMBA_STEP_ACCOUNT = """
echo "Step 1: the newton-ops account"

if samba-tool user show "${OPS_NAME}" >/dev/null 2>&1; then
    echo "  newton-ops exists."
elif [ "${IS_PDC}" = "yes" ]; then
    # The password is generated by samba-tool and it is thrown away: it
    # is never shown and it is never stored.
    samba-tool user create "${OPS_NAME}" --random-password
    echo "  newton-ops was created with a random password. It was not shown and it was not stored."
else
    # The account is created on the PDC and it reaches the other
    # controllers by replication.  Wait for it.
    DEADLINE=$(( $(date +%s) + 600 ))
    while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
        sleep 15
        if samba-tool user show "${OPS_NAME}" >/dev/null 2>&1; then break; fi
    done
    if ! samba-tool user show "${OPS_NAME}" >/dev/null 2>&1; then
        echo "the newton-ops account has not reached this controller within 10 minutes; run this script again later" >&2
        exit 1
    fi
    echo "  newton-ops reached this controller."
fi

OPS_SHOW="$(samba-tool user show "${OPS_NAME}" 2>/dev/null || true)"
OPS_DN="$(printf '%s\\n' "${OPS_SHOW}" | sed -n 's/^dn: //p')"
CURRENT_UAC="$(printf '%s\\n' "${OPS_SHOW}" | sed -n 's/^userAccountControl: //p')"
OPS_SID="$(ldbsearch -H "${SAMBA_LDB}" -b "${OPS_DN}" --scope=base '(objectClass=*)' objectSid 2>/dev/null | ldif_value objectSid | head -n 1 || true)"
if [ -z "${OPS_DN}" ] || [ -z "${CURRENT_UAC}" ] || [ -z "${OPS_SID}" ]; then
    echo "the newton-ops account could not be read" >&2
    exit 1
fi
case "${OPS_SID}" in
    S-1-5-21-*-*) ;;
    *)
        echo "the objectSid of newton-ops is not a domain SID" >&2
        exit 1
        ;;
esac

# The account may not be delegated: the bit 0x100000 of the
# userAccountControl.
WANTED_UAC=$(( CURRENT_UAC | 1048576 ))
if [ "${WANTED_UAC}" != "${CURRENT_UAC}" ]; then
    cat > "${WORK_DIR}/uac.ldif" <<EOF
dn: ${OPS_DN}
changetype: modify
replace: userAccountControl
userAccountControl: ${WANTED_UAC}
EOF
    if ! ldbmodify -H "${SAMBA_LDB}" "${WORK_DIR}/uac.ldif" >/dev/null 2>&1; then
        echo "the userAccountControl of newton-ops could not be written" >&2
        exit 1
    fi
    echo "  newton-ops may not be delegated."
fi

# The transitive groups of the account may hold no privileged group.
if ! TOKEN_GROUPS="$(ldbsearch -H "${SAMBA_LDB}" -b "${OPS_DN}" --scope=base '(objectClass=*)' tokenGroups 2>/dev/null | ldif_value tokenGroups)"; then
    echo "the groups of newton-ops could not be read; nothing after this point was changed" >&2
    exit 1
fi
if [ -z "${TOKEN_GROUPS}" ]; then
    echo "the groups of newton-ops could not be read; nothing after this point was changed" >&2
    exit 1
fi
for group_sid in ${TOKEN_GROUPS}; do
    if is_privileged_sid "${group_sid}"; then
        echo "newton-ops holds a privileged group (${group_sid}); fix it before running this script again" >&2
        exit 1
    fi
done
echo "  newton-ops holds no privileged group."

# The account may hold no right that replicates the directory.  That
# check is the check of AD-A-51 of SPEC-1.3, run against newton-ops.
# The helper tells the two refusals apart with its exit code: 1 is an
# account that holds a right that replicates the directory and 2 is a
# check that could not be made.  The script prints the line of the
# case, and only that one.
RIGHTS_STATUS=0
python3 "${WORK_DIR}/ad_write_setup.py" rights "${DOMAIN_DN}" "${SCHEMA_DN}" "${SAMBA_LDB}" "${OPS_SID}" ${TOKEN_GROUPS} || RIGHTS_STATUS=$?
if [ "${RIGHTS_STATUS}" -ne 0 ]; then
    case "${RIGHTS_STATUS}" in
        1)
            echo "fix the rights of newton-ops before running this script again" >&2
            ;;
        *)
            echo "newton-ops could not be checked against the replication rights of this domain; fix it before running this script again" >&2
            ;;
    esac
    exit 1
fi
"""


_SAMBA_STEP_DELEGATION = """
echo "Step 2: the delegation"

if [ "${IS_PDC}" != "yes" ]; then
    echo "delegation: done on the PDC"
else
    # The GUIDs of the classes and of the attributes are read from the
    # schema of this domain, at this moment.  No GUID of a schema
    # object is typed in this script.
    OUS_JOINED="$(printf '%s|' "${DELEGATED_OUS[@]}")"
    python3 "${WORK_DIR}/ad_write_setup.py" delegate "${OUS_JOINED}" "${DOMAIN_DN}" "${SCHEMA_DN}" "${SAMBA_LDB}" "${OPS_SID}"
fi
"""


_SAMBA_STEP_KEY = """
echo "Step 3: the approval key"

install -d -m 0755 -o root -g root "${CONFIG_DIR}"

# The passphrase is asked here, on the domain controller, twice, and it
# is never echoed.  The key is derived inside the script and it is never
# shown: only its fingerprint is printed.  The key is the key of the
# domain: it is derived with the name of the device that stands for the
# domain as its salt, so every controller of the domain holds the same
# K (SPEC-1.4-REQUEST section 1).
FINGERPRINT="$(python3 "${WORK_DIR}/approval.py" "${DOMAIN_DEVICE}" "${APPROVAL_KEY_PATH}")"
if [ -z "${FINGERPRINT}" ]; then
    echo "the approval key could not be installed" >&2
    exit 1
fi
chown root:root "${APPROVAL_KEY_PATH}"
chmod 0600 "${APPROVAL_KEY_PATH}"
echo "The approval key is installed. Its fingerprint is ${FINGERPRINT}"
echo "Compare that fingerprint with the one the Newton host printed."
"""


_SAMBA_STEP_FILES = """
echo "Step 4: the files"

install -d -m 0755 -o root -g root /usr/local/sbin
install -d -m 0755 -o root -g root "${CONFIG_DIR}"
install -d -m 0755 -o root -g root /var/lib/newton-ad
install -d -m 0700 -o root -g root "${TX_DIR}"

cat > "${WORK_DIR}/helper.b64" <<'NEWTON_AD_BLOB_EOF'
@@HELPER@@
NEWTON_AD_BLOB_EOF
base64 -d "${WORK_DIR}/helper.b64" > "${WORK_DIR}/newton-ad-samba-write"
install_blob "${WORK_DIR}/newton-ad-samba-write" "${HELPER_PATH}" 0755 '@@HELPER_HASH@@'

# The device name the helper of this controller answers to: the name of
# the device that stands for the domain, the same on every controller
# of the domain.  A request names the domain, and the helper refuses
# with `schema` when the name differs from this one.
printf '%s\\n' "${DOMAIN_DEVICE}" > "${WORK_DIR}/device.txt"
install -m 0644 -o root -g root "${WORK_DIR}/device.txt" "${DEVICE_FILE}"
echo "  the helper, the device name and the transaction store are in place."
"""


_SAMBA_STEP_KEYTAB = """
echo "Step 5: the keytab"

# The write identity is a keytab of its own, made on every domain
# controller, from the sam.ldb of that controller.  No password of the
# account is ever stored or moved.
PRINCIPAL="${OPS_NAME}@${REALM}"
if [ ! -f "${KEYTAB_PATH}" ] || ! klist -k "${KEYTAB_PATH}" 2>/dev/null | grep -q "${PRINCIPAL}"; then
    samba-tool domain exportkeytab "${KEYTAB_PATH}" --principal="${PRINCIPAL}"
    chown root:root "${KEYTAB_PATH}"
    chmod 0600 "${KEYTAB_PATH}"
    echo "  the keytab of ${PRINCIPAL} was exported."
else
    echo "  the keytab of ${PRINCIPAL} is in place."
fi

# The keytab is proved: it gives a ticket, into a private ccache under
# /run, and the ccache is removed right after.
CCACHE_DIR="$(mktemp -d /run/newton-ad-keytab.XXXXXX)"
chmod 0700 "${CCACHE_DIR}"
if env KRB5CCNAME="FILE:${CCACHE_DIR}/ccache" kinit -k -t "${KEYTAB_PATH}" "${PRINCIPAL}"; then
    echo "  the keytab gives a ticket for ${PRINCIPAL}."
else
    rm -rf "${CCACHE_DIR}"
    echo "the keytab does not give a ticket for ${PRINCIPAL}" >&2
    exit 1
fi
rm -rf "${CCACHE_DIR}"
"""


_SAMBA_STEP_LOGIN = """
echo "Step 6: the login"

if ! getent -s files passwd "${LOGIN_NAME}" >/dev/null 2>&1; then
    useradd --home-dir "${HOME_DIR}" --shell /bin/sh --password '!' "${LOGIN_NAME}"
    echo "  the local account ${LOGIN_NAME} was created. It has no password, so it cannot log in with one."
else
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
    echo "  the local account ${LOGIN_NAME} exists."
fi

mkdir -p "${HOME_DIR}/.ssh"
chown root:root "${HOME_DIR}" "${HOME_DIR}/.ssh"
chmod 0755 "${HOME_DIR}" "${HOME_DIR}/.ssh"

printf '%s\\n' "${KEY_LINE}" > "${WORK_DIR}/authorized_keys"
install -m 0644 -o root -g root "${WORK_DIR}/authorized_keys" "${KEYFILE}"

# The sudoers line is checked with visudo before it is put in place,
# and it is the last thing the script writes.
SUDOERS_TMP='/etc/sudoers.d/.newton-ops-ssh.newton'
printf '%s\\n' "${SUDOERS_LINE}" > "${SUDOERS_TMP}"
chmod 0440 "${SUDOERS_TMP}"
chown root:root "${SUDOERS_TMP}"
if visudo -cf "${SUDOERS_TMP}" >/dev/null; then
    install -m 0440 -o root -g root "${SUDOERS_TMP}" "${SUDOERS_FILE}"
    rm -f "${SUDOERS_TMP}"
else
    rm -f "${SUDOERS_TMP}"
    echo "visudo refused the sudoers line. Nothing was installed." >&2
    exit 1
fi
visudo -cf "${SUDOERS_FILE}"
"""


_SAMBA_STEP_INVENTORY = """
echo "Step 7: the inventory entry"

cat <<EOF

[devices.${DEVICE}]
platform = "ad-samba-write"
ad_domain = "${DOMAIN_DEVICE}"
ad_domain_guid = "${DOMAIN_GUID}"
host = "${WRITE_HOST}"
user = "${LOGIN_NAME}"
key_file = "<the private key of the write key, on the Newton host>"
known_hosts = "<the pinned known_hosts of the controller>"
domain = "${DOMAIN}"

The installed public key (sha256): @@KEYSHA@@
The key of this controller is ${KEYFILE}
The ad_domain of the entry is the inventory name of the device that stands for the domain: the PDC emulator's own entry. On every other DC, run the setup with --domain-device <that name>.
The key_file and known_hosts lines of the entry are placeholders the owner fills in.
EOF
"""


# ---- the command line --------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    """The command line of the setup tool of the write path."""
    parser = argparse.ArgumentParser(
        prog="newton-ad-setup",
        description=(
            "Print the owner's setup script for an Active Directory write "
            "host, or record the fingerprint of an approval key. The "
            "script is printed, never run."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser(
        "write",
        help="print the setup script of one write host",
    )
    write.add_argument(
        "platform",
        choices=("windows", "samba"),
        help="the write platform to set up",
    )
    write.add_argument(
        "--domain",
        required=True,
        help="the DNS name of the domain",
    )
    write.add_argument(
        "--pubkey",
        required=True,
        help="the path of the public key of the write key",
    )
    write.add_argument(
        "--device",
        required=True,
        help="the name of the inventory device",
    )
    write.add_argument(
        "--domain-device",
        dest="domain_device",
        default=None,
        metavar="NAME",
        help=(
            "the inventory name of the device that stands for the "
            "domain; the default is the value of --device"
        ),
    )
    write.add_argument(
        "--host",
        required=True,
        help="the host name or IP address of the write host",
    )
    write.add_argument(
        "--ou",
        required=True,
        action="append",
        dest="ous",
        metavar="DN",
        help="a delegated location of the domain; give it once per location",
    )
    key = commands.add_parser(
        "approval-key",
        help="record the fingerprint of the approval key of a device",
    )
    key.add_argument("device", help="the name of the inventory device")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Print the setup script of one write host, or record a fingerprint."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "approval-key":
            return approval_key(args.device)
        pubkey = _read_public_key(Path(args.pubkey))
        # Without --domain-device the entry names the device of --device.
        domain_device = args.device if args.domain_device is None else args.domain_device
        if args.platform == "samba":
            script = samba_write_script(
                domain=args.domain,
                pubkey=pubkey,
                device=args.device,
                host=args.host,
                ous=args.ous,
                domain_device=domain_device,
            )
        else:
            script = windows_write_script(
                domain=args.domain,
                pubkey=pubkey,
                device=args.device,
                host=args.host,
                ous=args.ous,
                domain_device=domain_device,
            )
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: the setup script cannot be built: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(script)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
