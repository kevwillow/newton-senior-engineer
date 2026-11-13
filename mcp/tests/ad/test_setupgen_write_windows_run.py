"""What a real Windows DC found in the generated Windows write setup.

The script printed by ``scripts/newton-ad-setup write
windows`` ran as Administrator on the real Windows Server 2025 PDC
``WSBXDC1.win2.newton.test``, under Windows PowerShell 5.1.  It stopped
at step 0.  The nine defects below are the ones that run found, and
every test here runs the generated PowerShell against a fake of Active
Directory whose answers are the measured ones.

The tests run under the PowerShell of this machine, named by
``$NEWTON_PWSH``, default ``~/.local/opt/pwsh-7.4.6/pwsh``.  A test that
needs it fails the run when it is not there: the gate of the fix says the
PowerShell tests must RUN.

The helpers of these tests are in ``windows_run.py``: the model of the
domain, the runner under pwsh and the readers of the generated script.
The two fixtures they need are in the conftest of the directory.
"""

from __future__ import annotations

from pathlib import Path

from newton_mcp.ad import setupgen_write as write
from pwsh_path import PWSH
from windows_run import (
    ACL_FAKE,
    AD_FAKE,
    CREATOR_OWNER_SID,
    DOMAIN_DN,
    GUID_MACHINE_ACCOUNT_QUOTA,
    GUID_USER,
    GUID_USER_ACCOUNT_CONTROL,
    OPS_SID,
    OU,
    PDC_POLICY_PATH,
    ZERO_GUID,
    delegation_program,
    fake_model,
    powershell_function,
    powershell_prelude,
    recorded_calls,
    run_program,
    step_text,
)


# ---- W-1: the check of the domain controller --------------------------------


def test_the_parent_of_the_computer_dn_is_the_domain_controllers_ou(
    windows_script: str, tmp_path: Path
) -> None:
    """The parent of the computer account is the OU of the controllers.

    The computer account of a domain controller is
    ``CN=<name>,OU=Domain Controllers,<domain>``: the OU is the PARENT
    of the account, so the check of the step 0 has to read the parent
    of the distinguished name and not look for a prefix.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            powershell_function(windows_script, "Get-DnParent"),
            "$cases = @(",
            "  @{ dn = 'CN=WSBXDC1,OU=Domain Controllers,DC=win2,DC=newton,DC=test';"
            " parent = 'OU=Domain Controllers,DC=win2,DC=newton,DC=test' },",
            "  @{ dn = 'CN=Doe\\, John,OU=Users,DC=win,DC=newton,DC=test';"
            " parent = 'OU=Users,DC=win,DC=newton,DC=test' },",
            "  @{ dn = 'OU=Users,DC=win,DC=newton,DC=test';"
            " parent = 'DC=win,DC=newton,DC=test' },",
            "  @{ dn = 'CN=only'; parent = '' }",
            ")",
            "foreach ($case in $cases) {",
            "  $parent = Get-DnParent $case.dn",
            "  if ($parent -ne $case.parent) {",
            "    Write-Output ('wrong parent: ' + $parent)",
            "    exit 1",
            "  }",
            "}",
            "Write-Output 'ok'",
        ]
    )

    result, _ = run_program(program, tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_the_step_0_compares_the_parent_of_the_computer_account(
    windows_script: str,
) -> None:
    """The step 0 does not look for a prefix of the computer account."""
    prechecks = step_text(windows_script, 0)
    assert "StartsWith($DcOuDn" not in prechecks
    assert "Get-DnParent" in prechecks


# ---- W-2: the filters of the searches ---------------------------------------


def test_no_ldap_filter_is_given_to_the_power_shell_filter(
    windows_script: str,
) -> None:
    """The searches of the directory use -LDAPFilter, never -Filter.

    The -Filter of the Active Directory module takes the filter
    language of PowerShell, and an LDAP filter in it is refused.
    """
    assert "-Filter '(" not in windows_script
    assert "-Filter \"(" not in windows_script
    assert "-LDAPFilter" in windows_script


# ---- W-3 and W-4: the account -----------------------------------------------


def test_the_account_is_created_without_the_user_account_control(
    windows_script: str, tmp_path: Path
) -> None:
    """New-ADUser is called without -UserAccountControl.

    The cmdlet has no such parameter, so a script that passes one is
    refused: "A parameter cannot be found that matches parameter name
    'UserAccountControl'".  The account is read again after it is
    created.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            "$isPdc = $true",
            step_text(windows_script, 1),
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(program, tmp_path, fake_model(users=[]))

    assert result.returncode == 0, result.stdout + result.stderr
    created = recorded_calls(recorded, "New-ADUser")
    assert len(created) == 1
    assert "userAccountControl" not in created[0]
    reads = recorded_calls(recorded, "Get-ADUser")
    assert any(
        "userAccountControl" in (read.get("properties") or []) for read in reads
    ), reads


def test_the_uac_is_read_before_it_is_replaced(
    windows_script: str, tmp_path: Path
) -> None:
    """The account is read with its userAccountControl, and the bit that
    is not delegated is added to the value that is there.

    A read without the property answers nothing, and the script would
    then REPLACE the value with 0x100000 alone, which drops the
    NORMAL_ACCOUNT bit of the account.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            "$isPdc = $true",
            step_text(windows_script, 1),
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(program, tmp_path, fake_model())

    assert result.returncode == 0, result.stdout + result.stderr
    writes = recorded_calls(recorded, "Set-ADObject")
    assert len(writes) == 1
    replaced = writes[0]["replace"]
    assert int(replaced["userAccountControl"]) == 512 + 0x100000


def test_an_account_without_its_uac_is_a_refusal(
    windows_script: str, tmp_path: Path
) -> None:
    """An account whose userAccountControl cannot be read is a refusal.

    The value 0 is refused too: it is never the value of a real
    account, and replacing it would drop the NORMAL_ACCOUNT bit.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            "$isPdc = $true",
            step_text(windows_script, 1),
        ]
    )
    model = fake_model()
    del model["users"][0]["userAccountControl"]

    result, _ = run_program(program, tmp_path, model)

    assert result.returncode != 0
    assert "userAccountControl" in (result.stdout + result.stderr)


# ---- W-5: the names of the schema -------------------------------------------


def test_the_schema_is_read_by_its_ldap_display_name(
    windows_script: str, tmp_path: Path
) -> None:
    """The GUID of a schema object is read by its LDAP display name.

    The name of an attribute is its CN ("User-Account-Control"), and
    the display name is the one the directory uses
    ("userAccountControl").  Only the objects that are needed are
    read, and every read is a search of one display name.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "$schemaDn = 'CN=Schema,CN=Configuration,' + $DomainDn",
            "$attribute = Get-SchemaGuid $schemaDn 'userAccountControl' 'attributeSchema'",
            f"if ($attribute -ne '{GUID_USER_ACCOUNT_CONTROL}') {{ exit 1 }}",
            "$class = Get-SchemaGuid $schemaDn 'user' 'classSchema'",
            f"if ($class -ne '{GUID_USER}') {{ exit 1 }}",
            "$quota = Get-SchemaGuid $schemaDn 'ms-DS-MachineAccountQuota' 'attributeSchema'",
            f"if ($quota -ne '{GUID_MACHINE_ACCOUNT_QUOTA}') {{ exit 1 }}",
            "foreach ($call in $script:FakeCalls) {",
            "  if (-not $call.ldapFilter) { continue }",
            "  if ($call.ldapFilter -notmatch '^\\(lDAPDisplayName=') {",
            "    Write-Output ('wrong filter: ' + $call.ldapFilter)",
            "    exit 1",
            "  }",
            "}",
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(program, tmp_path, fake_model())

    assert result.returncode == 0, result.stdout + result.stderr
    searches = [
        call for call in recorded_calls(recorded, "Get-ADObject") if call.get("ldapFilter")
    ]
    assert len(searches) == 3
    for search in searches:
        assert search["ldapFilter"].startswith("(lDAPDisplayName=")


# ---- W-6 and W-7: the grants and the check of the grants --------------------


def test_the_dsacls_calls_are_the_measured_forms(
    windows_script: str, tmp_path: Path
) -> None:
    """The grants are the measured dsacls calls.

    A property right is
    ``dsacls <OU> /I:S /G "<SID>:WP;<attribute>;<class>"``, a child
    right is ``dsacls <OU> /I:T /G "<SID>:CCDC;<class>"``, the right of
    a password reset is
    ``dsacls <OU> /I:S /G "S-1-3-0:CA;Reset Password;user>"``,
    and the right of the head of the domain is
    ``dsacls <domain> /G "<SID>:WP;ms-DS-MachineAccountQuota"``.  Every
    argument is its own element of the argument array.
    """
    result, recorded = run_program(delegation_program(windows_script), tmp_path, fake_model())

    assert result.returncode == 0, result.stdout + result.stderr
    wanted: list[list[str]] = []
    for attribute, klass in write.DELEGATED_PROPERTIES:
        wanted.append([OU, "/I:S", "/G", f"{OPS_SID}:WP;{attribute};{klass}"])
    wanted.append([OU, "/I:T", "/G", f"{OPS_SID}:CCDC;user"])
    wanted.append([OU, "/I:T", "/G", f"{OPS_SID}:CCDC;computer"])
    wanted.append([OU, "/I:S", "/G", f"{CREATOR_OWNER_SID}:CA;Reset Password;user"])
    wanted.append([DOMAIN_DN, "/G", f"{OPS_SID}:WP;ms-DS-MachineAccountQuota"])
    assert recorded["dsacls"] == wanted


def test_the_stored_rules_are_the_measured_ones(
    windows_script: str, tmp_path: Path
) -> None:
    """The rules the fake stores are the ones measured on the real DC.

    The property right is stored with the GUID of the attribute, the
    GUID of the class and the inheritance of the children only; the
    child right is stored with the GUID of the class and no inherited
    object type.  The location holds thirteen rules since the reset-password grant: the
    twelve of the delegation and the right of a password reset of the
    CREATOR OWNER.
    """
    result, recorded = run_program(delegation_program(windows_script), tmp_path, fake_model())

    assert result.returncode == 0, result.stdout + result.stderr
    rules = recorded["rules"][OU]
    assert len(rules) == 13
    first = rules[0]
    assert first["rights"] == "WriteProperty"
    assert first["objectType"] == GUID_USER_ACCOUNT_CONTROL
    assert first["inheritedObjectType"] == GUID_USER
    assert first["inheritanceType"] == "Descendents"
    assert int(first["objectFlags"]) == 3
    child = [rule for rule in rules if rule["rights"] == "CreateChild, DeleteChild"]
    assert len(child) == 2
    assert child[0]["inheritanceType"] == "All"
    assert child[0]["inheritedObjectType"] == ZERO_GUID
    assert int(child[0]["objectFlags"]) == 1
    head = recorded["rules"][DOMAIN_DN]
    assert len(head) == 1
    assert head[0]["objectType"] == GUID_MACHINE_ACCOUNT_QUOTA
    assert head[0]["inheritanceType"] == "None"


def test_a_rule_that_is_already_there_is_not_granted_again(
    windows_script: str, tmp_path: Path
) -> None:
    """A rule that is already there is read, field by field, and not
    granted again."""
    model = fake_model()
    model["acl"] = {
        OU: [
            {
                "sid": OPS_SID,
                "rights": "WriteProperty",
                "objectType": GUID_USER_ACCOUNT_CONTROL,
                "inheritedObjectType": GUID_USER,
                "inheritanceType": "Descendents",
                "objectFlags": 3,
            }
        ]
    }

    result, recorded = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr
    granted = [
        call
        for call in recorded["dsacls"]
        if call[-1].endswith(";userAccountControl;user")
    ]
    assert granted == []


def test_a_rule_with_another_object_type_is_granted_again(
    windows_script: str, tmp_path: Path
) -> None:
    """A rule that holds another object type is not the wanted one."""
    model = fake_model()
    model["acl"] = {
        OU: [
            {
                "sid": OPS_SID,
                "rights": "WriteProperty",
                "objectType": GUID_MACHINE_ACCOUNT_QUOTA,
                "inheritedObjectType": GUID_USER,
                "inheritanceType": "Descendents",
                "objectFlags": 3,
            }
        ]
    }

    result, recorded = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr
    granted = [
        call
        for call in recorded["dsacls"]
        if call[-1].endswith(";userAccountControl;user")
    ]
    assert len(granted) == 1


def test_a_grant_that_does_not_land_is_a_refusal(
    windows_script: str, tmp_path: Path
) -> None:
    """A grant that is not there after it was made is a refusal.

    The descriptor is read back the way it was read on the real DC: with the
    rules of the object, and not with the SDDL text.
    """
    model = fake_model()
    model["dsaclsWorks"] = False

    result, _ = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    assert "is not there after the grant" in (result.stdout + result.stderr)


# ---- W-8: the SeBatchLogonRight ---------------------------------------------


def test_the_template_is_read_and_written_as_unicode(
    windows_script: str, tmp_path: Path
) -> None:
    """The template of the policy is UTF-16LE with a BOM, and it stays
    that way.

    The holders of the right are kept, the SID of the write account is
    added to them, and a line that already holds it is not duplicated.
    """
    template = tmp_path / "GptTmpl.inf"
    template.write_bytes(
        "[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\n"
        "SeBatchLogonRight = *S-1-5-32-559,*S-1-5-32-551,*S-1-5-32-544\r\n".encode(
            "utf-16-le"
        )
        + b"\xff\xfe"
    )
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            powershell_function(windows_script, "Set-BatchLogonRightInTemplate"),
            f"$path = '{template}'",
            f"$changed = Set-BatchLogonRightInTemplate $path '{OPS_SID}'",
            "if (-not $changed) { Write-Output 'not changed'; exit 1 }",
            "$bytes = [System.IO.File]::ReadAllBytes($path)",
            "if ($bytes[0] -ne 0xff -or $bytes[1] -ne 0xfe) { exit 1 }",
            "if ($bytes[2] -ne 0x5b -or $bytes[3] -ne 0x00) { exit 1 }",
            "$lines = [System.IO.File]::ReadAllLines($path, [System.Text.Encoding]::Unicode)",
            "$count = 0",
            "foreach ($line in $lines) {",
            "  if ($line -match '^\\s*SeBatchLogonRight\\s*=') { $count++ }",
            "}",
            "if ($count -ne 1) { Write-Output ('lines: ' + $count); exit 1 }",
            "Write-Output 'ok'",
        ]
    )

    result, _ = run_program(program, tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"
    text = template.read_bytes().decode("utf-16-le")
    assert text.count("SeBatchLogonRight") == 1
    assert OPS_SID in text
    assert "*S-1-5-32-544" in text


def test_a_line_that_already_holds_the_sid_is_not_duplicated(
    windows_script: str, tmp_path: Path
) -> None:
    """A template that already holds the SID is left as it is."""
    template = tmp_path / "GptTmpl.inf"
    body = (
        "[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\n"
        f"SeBatchLogonRight = *{OPS_SID},*S-1-5-32-551\r\n"
    )
    template.write_bytes(body.encode("utf-16-le") + b"\xff\xfe")
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            powershell_function(windows_script, "Set-BatchLogonRightInTemplate"),
            f"$path = '{template}'",
            f"$changed = Set-BatchLogonRightInTemplate $path '{OPS_SID}'",
            "if ($changed) { Write-Output 'changed'; exit 1 }",
            "Write-Output 'ok'",
        ]
    )

    result, _ = run_program(program, tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"
    text = template.read_bytes().decode("utf-16-le")
    assert text.count("SeBatchLogonRight") == 1


def test_the_export_of_secedit_is_checked(
    windows_script: str, tmp_path: Path
) -> None:
    """The right is proved with the export of secedit.

    secedit prints the NAME of an account and the SID of a well known
    one, so every holder is resolved into a SID, and the SID of the
    write account has to be among them.  A line that is not there is a
    refusal.
    """
    rights = tmp_path / "rights.txt"
    rights.write_text(
        "[Unicode]\nUnicode=yes\n[Privilege Rights]\n"
        f"SeBatchLogonRight = newton-ops,*S-1-5-32-544,*S-1-5-32-551\n",
        encoding="utf-8",
    )
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            powershell_function(windows_script, "Resolve-NewtonAccountSid"),
            powershell_function(windows_script, "Test-BatchLogonRight"),
            f"function Resolve-NewtonAccountSid {{ param([string]$Name) return '{OPS_SID}' }}",
            f"$path = '{rights}'",
            f"if (-not (Test-BatchLogonRight $path '{OPS_SID}')) {{ exit 1 }}",
            f"if (Test-BatchLogonRight $path 'S-1-5-21-1-2-3-9999') {{ exit 1 }}",
            "$empty = '" + str(tmp_path / "empty.txt") + "'",
            "[System.IO.File]::WriteAllText($empty, \"[Unicode]`n\", (New-Object System.Text.UTF8Encoding($false)))",
            "if (Test-BatchLogonRight $empty '" + OPS_SID + "') { exit 1 }",
            "Write-Output 'ok'",
        ]
    )

    result, _ = run_program(program, tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_the_policy_is_read_by_its_own_name(
    windows_script: str, tmp_path: Path
) -> None:
    """The policy object is read by its own name, and its version is
    bumped with the version of the folder of the policy."""
    gpo = tmp_path / "gpo"
    gpo.mkdir()
    (gpo / "GPT.INI").write_text("[General]\r\nVersion=7\r\n", encoding="ascii")
    machine = gpo / "Machine" / "Microsoft" / "Windows NT" / "SecEdit"
    machine.mkdir(parents=True)
    (machine / "GptTmpl.inf").write_bytes(
        b"\xff\xfe[Unicode]\x00\r\x00\n\x00U\x00n\x00i\x00c\x00o\x00d\x00e\x00=\x00y\x00e\x00s\x00"
    )
    model = fake_model(
        objects=[
            {
                "DistinguishedName": f"CN={{6AC1786C-016F-11D2-945F-00C04fB984F9}},CN=Policies,CN=System,{DOMAIN_DN}",
                "objectClass": ["groupPolicyContainer"],
                "versionNumber": 3,
                "gPCFileSysPath": PDC_POLICY_PATH,
            }
        ],
        policyDir=str(gpo),
        userRights=(
            "[Unicode]\nUnicode=yes\n[Privilege Rights]\n"
            f"SeBatchLogonRight = newton-ops,*S-1-5-32-544\n"
        ),
    )
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Resolve-NewtonAccountSid { param([string]$Name) return '" + OPS_SID + "' }",
            "$isPdc = $true",
            f"$opsSid = '{OPS_SID}'",
            f"$GpoBackupRoot = '{tmp_path / 'gpo-backup'}'",
            # The backup of the policy is made by the step 0, and this
            # program runs the step 6 alone.
            "$backupDir = Join-Path $GpoBackupRoot '20261109-000000'",
            f"$env:TEMP = '{tmp_path}'",
            step_text(windows_script, 6),
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(program, tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr
    reads = recorded_calls(recorded, "Get-ADObject")
    identities = [read["identity"] for read in reads if read.get("identity")]
    assert (
        f"CN={{6AC1786C-016F-11D2-945F-00C04fB984F9}},CN=Policies,CN=System,{DOMAIN_DN}"
        in identities
    )
    writes = recorded_calls(recorded, "Set-ADObject")
    assert len(writes) == 1
    assert int(writes[0]["replace"]["versionNumber"]) == 4
    assert "Version=8" in (gpo / "GPT.INI").read_text(encoding="ascii")


# ---- W-9: the access control list of the install ----------------------------


def test_the_install_root_passes_the_install_check(
    windows_script: str, tmp_path: Path
) -> None:
    """The install root and the device file pass the install check.

    The check is the one of the write helper: the rules of the install
    grant a write to nobody except SYSTEM and Administrators.  The
    rules the folder of ProgramData inherits, including the write of
    BUILTIN\\Users, are gone.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{ACL_FAKE}'",
            powershell_function(windows_script, "Set-NewtonInstallAcl"),
            "$root = '" + str(tmp_path / "ad") + "'",
            "$device = '" + str(tmp_path / "device.txt") + "'",
            "Set-NewtonInstallAcl $root '" + OPS_SID + "' 'ReadAndExecute'"
            " 'ContainerInherit, ObjectInherit'",
            "Set-NewtonInstallAcl $device '" + OPS_SID + "' 'Read' 'None'",
            "if (-not (Test-NewtonSafeAcl $root)) { Write-Output 'root denied'; exit 1 }",
            "if (-not (Test-NewtonSafeAcl $device)) { Write-Output 'device denied'; exit 1 }",
            "Write-Output 'ok'",
        ]
    )

    result, _ = run_program(program, tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


def test_the_step_4_protects_the_root_and_the_device_file(
    windows_script: str,
) -> None:
    """The step 4 sets the rules of the install root and of the device
    file.

    The root gives the write account a read and an execute on the
    folder itself and nothing on the files beside it, and the device
    file gives it a read.
    """
    files = step_text(windows_script, 4)
    assert (
        "Set-NewtonInstallAcl $AdDir $opsSid 'ReadAndExecute' "
        "'ContainerInherit, ObjectInherit'" in files
    )
    assert "Set-NewtonInstallAcl $DeviceFilePath $opsSid 'Read' 'None'" in files


def test_an_unprotected_install_root_is_denied(
    windows_script: str, tmp_path: Path
) -> None:
    """The check has teeth: the rules of ProgramData are refused.

    The fake gives every folder the rules it inherits from ProgramData,
    and the write of BUILTIN\\Users is one of them.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{ACL_FAKE}'",
            "$root = '" + str(tmp_path / "ad") + "'",
            "if (Test-NewtonSafeAcl $root) { Write-Output 'allowed'; exit 1 }",
            "Write-Output 'ok'",
        ]
    )

    result, _ = run_program(program, tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"
