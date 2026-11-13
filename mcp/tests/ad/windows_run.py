"""The helpers of the tests that run the generated Windows write setup.

The tests of the Windows write setup run the PowerShell of the generated
script against a fake of Active Directory whose answers are the ones
measured on a real Windows Server 2025 domain controller,
and against a fake of the access control lists of the file system.

The fake of Active Directory is ``mcp/tests/ad/win_setup_fake.ps1`` and
the fake of the access control lists is
``mcp/tests/ad/win_setup_acl_fake.ps1``.  The model of the domain is
here: the GUIDs of the schema are the BYTES the directory answers for
a schemaIDGUID, and the rules of the objects are the ones
read back on the real DC.

The PowerShell of this machine is named by
``$NEWTON_PWSH``, default ``~/.local/opt/pwsh-7.4.6/pwsh``.  A test
that needs it fails the run when it is not there: the gate of the fixes
says the pwsh tests must RUN.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad import setupgen_write as write
from pwsh_path import PWSH


REPO_ROOT = Path(__file__).resolve().parents[3]
AD_FAKE = REPO_ROOT / "mcp" / "tests" / "ad" / "win_setup_fake.ps1"
ACL_FAKE = REPO_ROOT / "mcp" / "tests" / "ad" / "win_setup_acl_fake.ps1"

DOMAIN = "win.newton.test"
DOMAIN_DN = "DC=win,DC=newton,DC=test"
OU = "OU=Users,DC=win,DC=newton,DC=test"
DEVICE = "windc1"
HOST = "windc1.win.newton.test"
OPS_SID = "S-1-5-21-1-2-3-1105"

#: The FQDN of the PDC of the domain.  It is the answer of
#: ``(Get-ADDomain).PDCEmulator``, and the share of the SYSVOL of the
#: policy is under it.
PDC = HOST

#: The GUID of the Default Domain Controllers Policy, as measured on
#: the controller.
DEFAULT_DC_POLICY_GUID = "6AC1786C-016F-11D2-945F-00C04fB984F9"

#: The NTDS Settings object of the PDC.  It is the role owner of the
#: domain, and the rootDSE of the controller names it.
ROLE_OWNER = (
    "CN=NTDS Settings,CN=WINDC1,CN=Servers,CN=Default-First-Site-Name,"
    f"CN=Sites,CN=Configuration,{DOMAIN_DN}"
)

#: The path of the folder of the Default Domain Controllers Policy, the
#: way the directory answers it: the share of the SYSVOL of the PDC.
PDC_POLICY_PATH = (
    "\\\\" + PDC + "\\SysVol\\" + DOMAIN + "\\Policies\\{" + DEFAULT_DC_POLICY_GUID + "}"
)

#: The GUIDs measured on the DC.  The attribute
#: ``userAccountControl`` and the class ``user`` are the two of
#: MEASURED-2026-11-09.md; the quota of the head of the domain was
#: measured on the same controller.
GUID_USER_ACCOUNT_CONTROL = "bf967a68-0de6-11d0-a285-00aa003049e2"
GUID_USER = "bf967aba-0de6-11d0-a285-00aa003049e2"
GUID_MACHINE_ACCOUNT_QUOTA = "d064fb68-1480-11d3-91c1-0000f87a57d4"
ZERO_GUID = "00000000-0000-0000-0000-000000000000"

#: The GUID of the right of a password reset, the one read back on the
#: controller after the reset-password grant.  It is an extended
#: right and not a schema object: the script reads it from the
#: extended rights of the domain when it runs, and it checks it against
#: this value.
GUID_RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"

#: The objectGUID of the domain head.  The directory answers it as a
#: GUID value; the fake holds it as its text, which the [guid] cast of
#: the script reads the same way.
DOMAIN_HEAD_GUID = "af9619ff-8b86-d011-b42d-00c04fc964ff"

#: The name of the right of a password reset.  The name of the object
#: is its CN, and the display name of the object is another attribute:
#: a lookup by the display name finds nothing at all, as
#: measured on the real controller ("by name Reset Password: 0").
RESET_PASSWORD_RIGHT_CN = "User-Force-Change-Password"

#: The display name of that right.  It is the name the ace of dsacls
#: carries, and that form was measured to work.
RESET_PASSWORD_RIGHT = "Reset Password"

#: The SID of CREATOR OWNER.  The right of a password reset is granted
#: to it and not to the write account: the write account may then set
#: the password of the accounts it creates, and of no other account.
CREATOR_OWNER_SID = "S-1-3-0"

#: The container of the extended rights of the domain.  The rights that
#: are not rights of the schema live there, and a search of the schema
#: finds nothing at all.
EXTENDED_RIGHTS_DN = "CN=Extended-Rights,CN=Configuration," + DOMAIN_DN


def reset_password_right() -> dict[str, Any]:
    """The right of a password reset, as measured on a real DC.

    The dn is the one of the real controller, the name of the object is
    its CN, the display name is the one the directory shows and the
    GUID is the one of the right.  The shape that the model held before
    the fix (``CN=Reset Password`` with the name "Reset Password") is
    invented, and the real object is this one.
    """
    return {
        "dn": f"CN={RESET_PASSWORD_RIGHT_CN},{EXTENDED_RIGHTS_DN}",
        "objectClass": ["controlAccessRight"],
        "name": RESET_PASSWORD_RIGHT_CN,
        "cn": RESET_PASSWORD_RIGHT_CN,
        "displayName": RESET_PASSWORD_RIGHT,
        "rightsGuid": GUID_RESET_PASSWORD,
    }


def guid_bytes(guid: str) -> list[int]:
    """The sixteen bytes of a GUID, in the order of .NET.

    The first three fields of a GUID are little endian and the last
    eight bytes are as they are.  This is the order of the byte array
    that the directory answers for a schemaIDGUID, and it is the order
    that ``[guid][byte[]]`` reads.
    """
    text = guid.replace("-", "")
    first = bytes.fromhex(text[0:8])[::-1]
    second = bytes.fromhex(text[8:12])[::-1]
    third = bytes.fromhex(text[12:16])[::-1]
    rest = bytes.fromhex(text[16:32])
    return list(first + second + third + rest)


def guid_text(raw: bytes) -> str:
    """The text of a GUID, from the bytes the directory answers.

    It is the way round of :func:`guid_bytes`: the first three fields
    of a GUID are little endian and the last eight bytes are as they
    are.
    """
    first = raw[0:4][::-1]
    second = raw[4:6][::-1]
    third = raw[6:8][::-1]
    rest = raw[8:16]
    return "-".join(
        [
            first.hex(),
            second.hex(),
            third.hex(),
            rest[0:2].hex(),
            rest[2:8].hex(),
        ]
    )


def schema_guid(display_name: str) -> str:
    """The GUID of an object of the measured schema, as text."""
    for row in SCHEMA:
        if row["lDAPDisplayName"] == display_name:
            return guid_text(bytes(row["schemaIDGUID"]))
    raise KeyError(display_name)


#: The schema of the domain, as measured: the name of
#: an attribute is its CN ("User-Account-Control") and its LDAP display
#: name is the one the directory uses ("userAccountControl").  The
#: schemaIDGUID of every object is the byte array of the GUID, the way
#: the directory answers it.
SCHEMA: tuple[dict[str, Any], ...] = (
    {
        "dn": "CN=userAccountControl,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["attributeSchema"],
        "name": "User-Account-Control",
        "lDAPDisplayName": "userAccountControl",
        "schemaIDGUID": guid_bytes(GUID_USER_ACCOUNT_CONTROL),
    },
    {
        "dn": "CN=msDS-SupportedEncryptionTypes,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["attributeSchema"],
        "name": "msDS-SupportedEncryptionTypes",
        "lDAPDisplayName": "msDS-SupportedEncryptionTypes",
        "schemaIDGUID": guid_bytes("bf967a7c-0de6-11d0-a285-00aa003049e2"),
    },
    {
        "dn": "CN=lockoutTime,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["attributeSchema"],
        "name": "Lockout-Time",
        "lDAPDisplayName": "lockoutTime",
        "schemaIDGUID": guid_bytes("bf967a86-0de6-11d0-a285-00aa003049e2"),
    },
    {
        "dn": "CN=name,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["attributeSchema"],
        "name": "Name",
        "lDAPDisplayName": "name",
        "schemaIDGUID": guid_bytes("bf967a0e-0de6-11d0-a285-00aa003049e2"),
    },
    {
        "dn": "CN=cn,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["attributeSchema"],
        "name": "Common-Name",
        "lDAPDisplayName": "cn",
        "schemaIDGUID": guid_bytes("bf967a0f-0de6-11d0-a285-00aa003049e2"),
    },
    {
        "dn": "CN=member,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["attributeSchema"],
        "name": "Member",
        "lDAPDisplayName": "member",
        "schemaIDGUID": guid_bytes("bf9679c0-0de6-11d0-a285-00aa003049e2"),
    },
    {
        "dn": "CN=ms-DS-MachineAccountQuota,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["attributeSchema"],
        "name": "ms-DS-MachineAccountQuota",
        "lDAPDisplayName": "ms-DS-MachineAccountQuota",
        "schemaIDGUID": guid_bytes(GUID_MACHINE_ACCOUNT_QUOTA),
    },
    {
        "dn": "CN=user,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["classSchema"],
        "name": "user",
        "lDAPDisplayName": "user",
        "schemaIDGUID": guid_bytes(GUID_USER),
    },
    {
        "dn": "CN=computer,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["classSchema"],
        "name": "computer",
        "lDAPDisplayName": "computer",
        "schemaIDGUID": guid_bytes("bf967a86-0de6-11d0-a285-00aa003049e2"),
    },
    {
        "dn": "CN=group,CN=Schema,CN=Configuration," + DOMAIN_DN,
        "objectClass": ["classSchema"],
        "name": "group",
        "lDAPDisplayName": "group",
        "schemaIDGUID": guid_bytes("bf967a9c-0de6-11d0-a285-00aa003049e2"),
    },
)


def _key_body(key_type: str) -> str:
    """The base64 body of a synthetic public key of one type."""
    payload = key_type.encode("ascii")
    blob = len(payload).to_bytes(4, "big") + payload + bytes(32)
    import base64

    return base64.b64encode(blob).decode("ascii")


PUBLIC_KEY = f"ssh-ed25519 {_key_body('ssh-ed25519')}"


@pytest.fixture
def helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The stub write helpers of this build."""
    stub = tmp_path / "helpers"
    stub.mkdir()
    windows = stub / "write.ps1"
    windows.write_text("# the stub of the Windows write helper\n", encoding="utf-8")
    samba = stub / "newton-ad-samba-write"
    samba.write_text("#!/bin/sh\n# the stub of the Samba write helper\n", encoding="utf-8")
    monkeypatch.setattr(write, "WRITE_HELPER_PATH", windows)
    monkeypatch.setattr(write, "SAMBA_WRITE_HELPER_PATH", samba)
    return stub


@pytest.fixture
def windows_script(helpers: Path) -> str:
    """The printed Windows write setup script."""
    return write.windows_write_script(
        domain=DOMAIN,
        pubkey=write.validate_public_key(PUBLIC_KEY),
        device=DEVICE,
        host=HOST,
        ous=[OU],
    )


def step_text(script: str, number: int) -> str:
    """The text of one step of a script."""
    lines = script.splitlines()
    marker = f"Step {number}:"
    start = next(index for index, line in enumerate(lines) if marker in line)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.match(r'^\s*(?:Write-Host|echo)\s+.{0,4}Step \d+:', lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def powershell_function(script: str, name: str) -> str:
    """The text of one function of the generated PowerShell script."""
    lines = script.splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith(f"function {name}")
    )
    end = next(index for index in range(start + 1, len(lines)) if lines[index] == "}")
    return "\n".join(lines[start : end + 1])


def powershell_prelude(script: str) -> str:
    """The header and the functions of the generated PowerShell script."""
    lines = script.splitlines()
    end = next(
        index for index, line in enumerate(lines) if line.startswith("Write-Host 'Step 0:")
    )
    return "\n".join(lines[:end])


def fake_model(**overrides: Any) -> dict[str, Any]:
    """The fake of the domain, with the measured answers."""
    built: dict[str, Any] = {
        "domain": DOMAIN,
        "domainDn": DOMAIN_DN,
        "netbios": "WIN",
        "computerName": "WINDC1",
        "computerDn": f"CN=WINDC1,OU=Domain Controllers,{DOMAIN_DN}",
        "roleOwner": ROLE_OWNER,
        "pdcEmulator": PDC,
        "dsaclsWorks": True,
        "userRights": "",
        "objects": [
            {
                "dn": DOMAIN_DN,
                "objectClass": ["domainDNS"],
                "fSMORoleOwner": ROLE_OWNER,
                "objectGuid": DOMAIN_HEAD_GUID,
            },
            {"dn": OU, "objectClass": ["organizationalUnit"]},
            reset_password_right(),
        ],
        "schema": [dict(row) for row in SCHEMA],
        "users": [
            {
                "sam": "newton-ops",
                "SamAccountName": "newton-ops",
                "Name": "newton-ops",
                "DistinguishedName": f"CN=newton-ops,{OU}",
                "SID": OPS_SID,
                "userAccountControl": 512,
                "tokenGroups": ["S-1-5-21-1-2-3-513"],
            }
        ],
        "acl": {},
        "newUser": {
            "DistinguishedName": f"CN=newton-ops,{OU}",
            "SID": OPS_SID,
            "tokenGroups": ["S-1-5-21-1-2-3-513"],
        },
    }
    built.update(overrides)
    return built


def run_program(
    program: str,
    tmp_path: Path,
    model: dict[str, Any] | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    """The program runs under pwsh, with the fake of Active Directory."""
    if not PWSH.exists():
        pytest.fail("the gate of the Windows setup tests requires pwsh to run")
    path = tmp_path / "program.ps1"
    path.write_text(program, encoding="utf-8")
    env = dict(os.environ)
    out = tmp_path / "out.json"
    env["NEWTON_FAKE_OUT"] = str(out)
    # The folder of the backups of the policy: the real script backs
    # the policy up under the install root of the controller, and that
    # path is a name of a folder on the machine of the tests.
    env["NEWTON_FAKE_GPO_BACKUP_ROOT"] = str(tmp_path / "gpo-backup")
    if model is not None:
        model_path = tmp_path / "model.json"
        model_path.write_text(json.dumps(model), encoding="utf-8")
        env["NEWTON_FAKE_AD"] = str(model_path)
    result = subprocess.run(
        [str(PWSH), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    recorded: dict[str, Any] = {}
    if out.exists():
        recorded = json.loads(out.read_text(encoding="utf-8"))
    return result, recorded


def recorded_calls(recorded: dict[str, Any], cmdlet: str) -> list[dict[str, Any]]:
    """The recorded calls of one cmdlet."""
    all_calls = recorded.get("calls", [])
    return [call for call in all_calls if call.get("cmdlet") == cmdlet]


def delegation_program(script: str) -> str:
    """The program that runs the step 2 of the script against the fake."""
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(script),
            "$isPdc = $true",
            f"$opsSid = '{OPS_SID}'",
            step_text(script, 2),
            "@{ dsacls = @($script:FakeDsacls); calls = @($script:FakeCalls);"
            " rules = $script:FakeAclRules } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )


#: The PowerShell that puts the folder of the backups of the policy in
#: the sandbox.
#:
#: The real script backs the policy up under the install root of the
#: controller, ``C:\\ProgramData\\Newton\\ad\\gpo-backup``.  On the
#: machine of the tests that path is the name of a folder, and a run
#: that made it would leave it behind: the folder of the sandbox stands
#: for it, and the runner names it in the environment.
BACKUP_ROOT_LINE = "$GpoBackupRoot = $env:NEWTON_FAKE_GPO_BACKUP_ROOT"


def step_zero_without_the_elevation_check(script: str) -> str:
    """The step 0 without the check of the elevation.

    The check is a Windows behaviour: ``WindowsIdentity`` does not
    exist on the machine of the tests, so the fake of the session
    answers that the session is elevated.  Every other check of the
    step 0 runs as the script has it.
    """
    lines = step_text(script, 0).splitlines()
    kept: list[str] = []
    skipping = False
    for line in lines:
        if line.startswith("$identity = "):
            skipping = True
            continue
        if skipping:
            if line.strip() == "}":
                skipping = False
            continue
        kept.append(line)
    assert not skipping, "the check of the elevation was not removed"
    return "\n".join(kept)
