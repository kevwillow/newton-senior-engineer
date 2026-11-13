"""The owner's setup script for the 1.4 write path.

The script is printed, never run: the owner reads it and runs it as a
Domain Admin on the domain controller.  The tests here read the printed
script and check that it carries every step of the contract, that the
pre-checks come before any change, that the delegation runs on the PDC
only, that the sshd restart is the last step, that it carries no secret
and no GUID of a schema object, and that the two scripts agree with
``derive_k`` and ``approval_fingerprint`` on the approval key.
"""

from __future__ import annotations

import base64
import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from newton_mcp import approve
from newton_mcp.ad import setupgen_write as write
from newton_mcp.ad.write import inventory
from newton_mcp.server import load_inventory
from pwsh_path import PWSH


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "newton-ad-setup"

DOMAIN = "win.newton.test"
DOMAIN_DN = "DC=win,DC=newton,DC=test"
OU = "OU=Users,DC=win,DC=newton,DC=test"
DEVICE = "windc1"
HOST = "windc1.win.newton.test"
PASSPHRASE = "correct horse battery staple"

#: The objectGUID of the domain head, the format the loader accepts
#: (``AD_GUID_RE``), one per platform of the printed entries.
WIN_DOMAIN_GUID = "af9619ff-8b86-d011-b42d-00c04fc964ff"
SAMBA_DOMAIN_GUID = "bf9619ff-8b86-d011-b42d-00c04fc964ff"

#: The GUID of a schema object, of any shape.
GUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

#: The GUID of the Default Domain Controllers Policy.  It is not a
#: schema object: the contract names it.
DC_POLICY_GUID = "6AC1786C-016F-11D2-945F-00C04fB984F9"

#: The GUID of the right of a password reset.  It is not a schema
#: object either: it is an extended right, and the script types it as
#: the value the directory is checked against.
RESET_PASSWORD_GUID = "00299570-246d-11d0-a768-00aa006e0529"


def _key_body(key_type: str) -> str:
    """The base64 body of a synthetic public key of one type."""
    payload = key_type.encode("ascii")
    blob = len(payload).to_bytes(4, "big") + payload + bytes(32)
    return base64.b64encode(blob).decode("ascii")


KEY_BODY = _key_body("ssh-ed25519")
PUBLIC_KEY = f"ssh-ed25519 {KEY_BODY}"


@pytest.fixture
def helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The stub write helpers of this build.

    The two write helpers are built on other branches and they are not
    in this tree: the tests point the path constants of the module at
    small stub files.
    """
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


@pytest.fixture
def samba_script(helpers: Path) -> str:
    """The printed Samba write setup script."""
    return write.samba_write_script(
        domain="lab.newton.test",
        pubkey=write.validate_public_key(PUBLIC_KEY),
        device="sambadc1",
        host="sambadc1.lab.newton.test",
        ous=["OU=Users,DC=lab,DC=newton,DC=test"],
    )


def _step(text: str, number: int) -> str:
    """The text of one step of a script."""
    lines = text.splitlines()
    marker = f"Step {number}:"
    start = next(index for index, line in enumerate(lines) if marker in line)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.match(r'^\s*(?:Write-Host|echo)\s+.{0,4}Step \d+:', lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def _powershell_function(script: str, name: str) -> str:
    """The text of one function of the generated PowerShell script."""
    lines = script.splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith(f"function {name}")
    )
    end = next(index for index in range(start + 1, len(lines)) if lines[index] == "}")
    return "\n".join(lines[start : end + 1])


def _embedded_python(script: str, name: str) -> str:
    """The text of one program the generated bash script writes."""
    lines = script.splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if line.startswith(f'cat > "${{WORK_DIR}}/{name}"')
    )
    begin = start + 1
    end = next(
        index
        for index in range(begin, len(lines))
        if lines[index] == "NEWTON_AD_PY_EOF"
    )
    return "\n".join(lines[begin:end])


# ---- the step order ---------------------------------------------------------


def test_the_windows_script_holds_every_step(windows_script: str) -> None:
    """The steps of the script are in it, in the order of the contract."""
    steps = [
        "Step 0: the pre-checks",
        "Step 1: the newton-ops account",
        "Step 2: the delegation",
        "Step 3: the approval key",
        "Step 4: the files",
        "Step 5: the login",
        "Step 6: the SeBatchLogonRight",
        "Step 7: the inventory entry",
        "Step 8: the sshd restart",
    ]
    places = [windows_script.index(step) for step in steps]
    assert places == sorted(places)


def test_the_samba_script_holds_every_step(samba_script: str) -> None:
    """The steps of the script are in it, in the order of the contract."""
    steps = [
        "Step 0: the pre-checks",
        "Step 1: the newton-ops account",
        "Step 2: the delegation",
        "Step 3: the approval key",
        "Step 4: the files",
        "Step 5: the keytab",
        "Step 6: the login",
        "Step 7: the inventory entry",
    ]
    places = [samba_script.index(step) for step in steps]
    assert places == sorted(places)


def test_the_pre_checks_come_before_any_change(
    windows_script: str, samba_script: str
) -> None:
    """The pre-checks change nothing in the domain and they come first.

    A run that stops in the pre-checks must leave the domain as it was,
    so the pre-checks hold no command that changes anything of it.  The
    one file they write is the backup of the policy of the PDC, on the
    disk of the controller.
    """
    for script in (windows_script, samba_script):
        prechecks = _step(script, 0)
        for word in (
            "New-AD",
            "Set-AD",
            "Add-AD",
            "Remove-AD",
            "Set-Acl",
            "dsacls",
            "ldbmodify",
            "samba-tool user create",
            "install ",
            "useradd",
            "chmod",
            "chown",
            "exportkeytab",
        ):
            assert word not in prechecks, f"{word} is in the pre-checks"
    # The Samba pre-checks write nothing at all.
    assert "New-Item" not in _step(samba_script, 0)


def test_the_only_file_the_pre_checks_write_is_the_backup_of_the_policy(
    windows_script: str,
) -> None:
    """The step 0 creates the folder of the backup and nothing else.

    The backup of the policy of the PDC is a file on the disk of the
    controller: the domain is as it was when the run stops there.
    """
    prechecks = _step(windows_script, 0)

    assert prechecks.count("New-Item") == 1
    assert "New-Item -ItemType Directory -Path $backupDir -Force" in prechecks


def test_the_delegation_runs_on_the_pdc_only(
    windows_script: str, samba_script: str
) -> None:
    """The delegation runs on the PDC and nowhere else.

    The other domain controllers replicate the delegation, so a run on
    another controller changes nothing there.
    """
    windows = _step(windows_script, 2)
    assert "if (-not $isPdc) {" in windows
    assert "delegation: done on the PDC" in windows
    assert windows.index("if (-not $isPdc) {") < windows.index("& dsacls @dsaclsArgs")

    samba = _step(samba_script, 2)
    assert 'if [ "${IS_PDC}" != "yes" ]; then' in samba
    assert "delegation: done on the PDC" in samba
    assert samba.index('if [ "${IS_PDC}" != "yes" ]; then') < samba.index(
        "ad_write_setup.py\" delegate"
    )


def test_the_pdc_is_found_with_the_role_owner(
    windows_script: str, samba_script: str
) -> None:
    """The PDC is the controller whose rootDSE names the role owner."""
    assert "Get-ADRootDSE -Properties dsServiceName" in windows_script
    assert "fSMORoleOwner" in windows_script
    assert "dsServiceName" in samba_script
    assert "fSMORoleOwner" in samba_script


def test_the_sshd_restart_is_the_last_step(windows_script: str) -> None:
    """The restart of sshd is the last thing the script does.

    A restart of sshd that is a child of the SSH session dies with the
    session, so it goes through a one-shot SYSTEM task, and it is the
    last step of the script.
    """
    restart = windows_script.index("Step 8: the sshd restart")
    for number in range(0, 8):
        assert windows_script.index(f"Step {number}:") < restart
    assert "Register-ScheduledTask -TaskName $RestartTask" in windows_script
    assert "New-ScheduledTaskPrincipal -UserId 'SYSTEM'" in windows_script
    assert "Restart-Service sshd -Force" in windows_script
    assert "& $sshdExe -t" in windows_script
    assert windows_script.rstrip().endswith("}")


def test_the_sshd_configuration_is_put_back_when_it_is_refused(
    windows_script: str,
) -> None:
    """A refused configuration is put back the way it was read."""
    assert "sshd_config.bak-newton-write" in windows_script
    assert (
        "[System.IO.File]::WriteAllText($SshdConfig, $config, "
        "(New-Object System.Text.UTF8Encoding($false)))"
    ) in windows_script
    assert "sshd refused the configuration" in windows_script


# ---- the static checks ------------------------------------------------------


def test_the_script_never_uses_invoke_expression(
    windows_script: str, samba_script: str
) -> None:
    """No step builds a command out of text."""
    assert "Invoke-Expression" not in windows_script
    assert "Invoke-Expression" not in samba_script
    assert "eval " not in samba_script


def test_the_script_never_builds_a_plain_password(windows_script: str) -> None:
    """The password of the account is never a plain string.

    The secure string is built one character at a time, so the password
    is never a string that a module would log.
    """
    assert "-AsPlainText" not in windows_script
    assert "ConvertTo-SecureString" not in windows_script
    assert "$secure.AppendChar(" in windows_script


def test_the_script_never_holds_the_key(windows_script: str, samba_script: str) -> None:
    """The key is never printed and it is never in the text of the script.

    Only the fingerprint is shown, so that the owner may compare it with
    the one the Newton host printed.
    """
    key = approve.derive_k(PASSPHRASE.encode("utf-8"), DEVICE)
    fingerprint = approve.approval_fingerprint(key)
    for script in (windows_script, samba_script):
        assert key not in script
        assert fingerprint not in script
    assert "Write-Host ($keyHex" not in windows_script
    assert "print(key.hex())" not in samba_script
    assert "fingerprint" in windows_script
    assert "fingerprint" in samba_script


def test_dsacls_is_run_with_an_argv_array(windows_script: str) -> None:
    """dsacls is run with an argument array, never with a command string."""
    assert "$dsaclsArgs = @($ou, '/I:S', '/G', $ace)" in windows_script
    assert "$dsaclsArgs = @($ou, '/I:T', '/G', $ace)" in windows_script
    assert "$dsaclsArgs = @($DomainDn, '/G', $headAce)" in windows_script
    assert "& dsacls @dsaclsArgs" in windows_script
    for line in windows_script.splitlines():
        stripped = line.strip()
        if stripped.startswith("& dsacls"):
            assert "+" not in stripped, f"a command string is built: {line}"
            assert "$" not in stripped.split("@")[0], (
                f"the argument of dsacls is built: {line}"
            )


def test_samba_tool_is_run_with_an_argv_array(samba_script: str) -> None:
    """samba-tool is run with an argument array, never with a command
    string."""
    assert '["samba-tool", "dsacl", "set", "--objectdn", dn, "--sddl"' in samba_script
    assert '["samba-tool", "dsacl", "get", "--objectdn", dn]' in samba_script
    assert 'samba-tool domain exportkeytab "${KEYTAB_PATH}" --principal="${PRINCIPAL}"' in (
        samba_script
    )
    for line in samba_script.splitlines():
        stripped = line.strip()
        if stripped.startswith("samba-tool "):
            assert "+" not in stripped, f"a command string is built: {line}"


def test_the_windows_script_holds_no_guid_of_a_schema_object(
    windows_script: str,
) -> None:
    """No GUID of a schema object is typed in the script.

    The GUIDs of the script are the one of the Default Domain
    Controllers Policy and the one of the right of a password reset,
    and the contract names both.  The GUID of the right is typed as the
    value the directory is CHECKED against: the GUID that the
    script uses is the one the directory answered, and the read one is
    refused unless it is that value.
    """
    found = set(GUID_RE.findall(windows_script))
    assert found == {DC_POLICY_GUID, RESET_PASSWORD_GUID}


def test_the_samba_script_holds_no_guid_at_all(samba_script: str) -> None:
    """The Samba script reads every GUID from the schema at run time."""
    assert GUID_RE.findall(samba_script) == []


def test_the_script_holds_no_private_key(
    windows_script: str, samba_script: str
) -> None:
    """Only the public key of the write key is in the script."""
    for script in (windows_script, samba_script):
        assert f"ssh-ed25519 {KEY_BODY}" in script
        assert "PRIVATE KEY" not in script
        assert "BEGIN OPENSSH" not in script


# ---- the delegation ---------------------------------------------------------


def test_the_delegation_is_exactly_the_list_of_the_contract(
    windows_script: str, samba_script: str
) -> None:
    """The script grants the rights of SPEC-1.4 section 8, and no more."""
    expected = [
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
    ]
    assert write.DELEGATED_PROPERTIES == tuple(expected)
    for attribute, klass in expected:
        assert (
            f"@{{ right = 'WP'; objectType = 'property:{attribute}'; "
            f"inherited = '{klass}' }}"
        ) in windows_script
        assert f'("{attribute}", "{klass}")' in samba_script


def test_the_delegation_grants_the_child_rights(
    windows_script: str, samba_script: str
) -> None:
    """The create-child and delete-child rights are granted, per class.

    On Windows the measured dsacls form grants the two rights in ONE
    ace, ``CCDC``, and there is one ace per class of child.
    """
    assert "@{ right = 'CCDC'; objectType = 'user'; inherited = '' }" in windows_script
    assert "@{ right = 'CCDC'; objectType = 'computer'; inherited = '' }" in windows_script
    assert '("create", "user")' in samba_script
    assert '("delete", "user")' in samba_script
    assert '("create", "computer")' in samba_script
    assert '("delete", "computer")' in samba_script


def test_the_head_of_the_domain_gets_the_quota_right(
    windows_script: str, samba_script: str
) -> None:
    """The machine account quota is granted on the head of the domain, and
    it is not inherited."""
    assert "property:ms-DS-MachineAccountQuota" in windows_script
    assert "HEAD_PROPERTY = \"ms-DS-MachineAccountQuota\"" in samba_script
    assert 'wanted = ace(sid, WRITE_PROPERTY, head_guid, "", "")' in samba_script


def test_the_delegation_is_inherited_to_the_subtree(
    windows_script: str, samba_script: str
) -> None:
    """The rights of a delegated location are inherited to its subtree.

    On Windows the inheritance is asked for by the measured flags of
    dsacls: ``/I:S`` for a property right and ``/I:T`` for a right of
    the children.
    """
    assert "'/I:S'" in windows_script
    assert "'/I:T'" in windows_script
    assert '"OICI"' in samba_script


def test_each_ace_is_added_only_when_it_is_missing(
    windows_script: str, samba_script: str
) -> None:
    """An ACE that is already there is reported and not added again."""
    assert "Test-AcePresent" in windows_script
    assert "is present" in windows_script
    assert "is added" in windows_script
    assert "same_ace" in samba_script
    assert "is present" in samba_script
    assert "is added" in samba_script


# ---- the account ------------------------------------------------------------


def test_the_account_is_created_with_a_random_password(
    windows_script: str, samba_script: str
) -> None:
    """The password is generated inside the script and thrown away."""
    assert "New-Object 'System.Byte[]' 32" in windows_script
    assert "-AccountPassword $secure" in windows_script
    assert "It was not shown and it was not stored" in windows_script
    assert (
        'samba-tool user create "${OPS_NAME}" --random-password' in samba_script
    )
    assert "It was not shown and it was not stored" in samba_script


def test_the_account_may_not_be_delegated(
    windows_script: str, samba_script: str
) -> None:
    """The account is sensitive and cannot be delegated."""
    assert "0x100000" in windows_script
    assert "1048576" in samba_script
    assert "may not be delegated" in windows_script
    assert "may not be delegated" in samba_script


def test_the_privileged_groups_of_the_account_are_refused(
    windows_script: str, samba_script: str
) -> None:
    """The transitive groups of the account may hold no privileged group."""
    assert "tokenGroups" in windows_script
    assert "Test-PrivilegedSid" in windows_script
    assert "holds a privileged group" in windows_script
    assert "tokenGroups" in samba_script
    assert "is_privileged_sid" in samba_script
    assert "holds a privileged group" in samba_script
    for rid in (498, 512, 516, 518, 519, 520, 521, 525, 526, 527):
        assert str(rid) in windows_script
        assert str(rid) in samba_script
    for sid in write.PRIVILEGED_BUILTIN_SIDS:
        assert sid in windows_script
        assert sid in samba_script


def test_the_account_waits_for_the_replication(
    windows_script: str, samba_script: str
) -> None:
    """A controller that has not got the account yet waits for it."""
    assert "AddMinutes(10)" in windows_script
    assert "has not reached this controller within 10 minutes" in windows_script
    assert "600" in samba_script
    assert "has not reached this controller within 10 minutes" in samba_script


def test_the_replication_rights_are_refused(
    windows_script: str, samba_script: str
) -> None:
    """The account may hold no right that replicates the directory."""
    assert "Test-NoReplicationRight" in windows_script
    assert "replicates the directory" in windows_script
    assert '"rights"' in samba_script
    assert "replicates the directory" in samba_script


# ---- the files --------------------------------------------------------------


def test_the_helper_is_embedded_and_checked_against_its_hash(
    windows_script: str, samba_script: str, helpers: Path
) -> None:
    """The helper of the package is embedded and it is checked."""
    windows = (helpers / "write.ps1").read_bytes()
    samba = (helpers / "newton-ad-samba-write").read_bytes()
    assert hashlib.sha256(windows).hexdigest() in windows_script
    assert hashlib.sha256(samba).hexdigest() in samba_script
    assert "Get-FileHash -Algorithm SHA256" in windows_script
    assert "sha256sum" in samba_script


def test_the_helper_is_configured_with_the_domain_device(
    windows_script: str, samba_script: str
) -> None:
    """device.txt holds the name of the device that stands for the domain.

    A request names the domain (SPEC-1.4-REQUEST section 1: ``device``
    names the domain), so the helper of every DC answers to the domain
    device's name and not to this controller's own inventory name.
    """
    assert "$DeviceFilePath = 'C:\\ProgramData\\Newton\\ad\\device.txt'" in (
        windows_script
    )
    assert (
        '[System.IO.File]::WriteAllText($DeviceFilePath, $DomainDevice + "`n"'
        in windows_script
    )
    assert "WriteAllText($DeviceFilePath, $Device +" not in windows_script
    assert "DEVICE_FILE='/etc/newton-ad/device.txt'" in samba_script
    assert (
        'printf \'%s\\n\' "${DOMAIN_DEVICE}" > "${WORK_DIR}/device.txt"'
        in samba_script
    )
    assert 'printf \'%s\\n\' "${DEVICE}"' not in samba_script


def test_the_approval_key_is_derived_with_the_domain_device(
    windows_script: str, samba_script: str
) -> None:
    """The salt of the approval key is the domain device's name.

    Every DC of the domain holds the same K (SPEC-1.4-REQUEST section
    1), and the Newton host derives K once, for the device that stands
    for the domain: the derivation on the DC must salt with that name,
    or the key of a second DC never matches the one the host holds.
    """
    assert "Get-ApprovalKeyHex $passphrase $DomainDevice" in windows_script
    assert "Get-ApprovalKeyHex $passphrase $Device" not in windows_script
    assert 'approval.py" "${DOMAIN_DEVICE}" "${APPROVAL_KEY_PATH}"' in samba_script
    assert 'approval.py" "${DEVICE}"' not in samba_script
    # The passphrase is asked for the key of the domain device, the one
    # the owner also types on the Newton host.
    assert "('approval passphrase for ' + $DomainDevice)" in windows_script


def test_the_generated_lines_write_the_domain_device_into_the_device_file(
    helpers: Path, tmp_path: Path
) -> None:
    """What lands in the device file of a second DC is the domain device.

    The line each script carries is run as it is printed, with the
    assignments of a setup that names win-dc1 as the domain device of
    win-dc2.
    """
    windows = write.windows_write_script(
        domain=DOMAIN,
        pubkey=write.validate_public_key(PUBLIC_KEY),
        device="win-dc2",
        host="windc2.win.newton.test",
        ous=[OU],
        domain_device="windc1",
    )
    line = next(
        text
        for text in windows.splitlines()
        if text.startswith("[System.IO.File]::WriteAllText($DeviceFilePath")
    )
    device_file = tmp_path / "device.txt"
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"$DeviceFilePath = '{device_file}'",
            "$DomainDevice = 'windc1'",
            line,
            "Write-Output 'ok'",
        ]
    )
    path = tmp_path / "win-device.ps1"
    path.write_text(program, encoding="utf-8")
    result = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert device_file.read_text(encoding="utf-8") == "windc1\n"

    samba = write.samba_write_script(
        domain="lab.newton.test",
        pubkey=write.validate_public_key(PUBLIC_KEY),
        device="sambadc2",
        host="sambadc2.lab.newton.test",
        ous=["OU=Users,DC=lab,DC=newton,DC=test"],
        domain_device="sambadc1",
    )
    samba_line = next(
        text
        for text in samba.splitlines()
        if text.startswith("printf") and text.endswith('device.txt"')
    )
    work = tmp_path / "work"
    work.mkdir()
    script = "\n".join(
        [
            "DEVICE='sambadc2'",
            "DOMAIN_DEVICE='sambadc1'",
            f"WORK_DIR='{work}'",
            samba_line,
        ]
    )
    script_path = tmp_path / "samba-device.sh"
    script_path.write_text(script, encoding="utf-8")
    run = subprocess.run(
        ["bash", str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert (work / "device.txt").read_text(encoding="utf-8") == "sambadc1\n"


def test_the_transaction_store_is_protected(
    windows_script: str, samba_script: str
) -> None:
    """The transaction store is protected the way the contract says.

    On Windows SYSTEM and Administrators have full control and the write
    account may read the store, create files in it and write them, but
    it may not delete anything.  On Samba the store is root's alone.
    """
    assert "$TxDir = 'C:\\ProgramData\\Newton\\ad\\tx'" in windows_script
    assert "'Read, CreateFiles, WriteData'" in windows_script
    assert "TX_DIR='/var/lib/newton-ad/tx'" in samba_script
    assert "install -d -m 0700 -o root -g root" in samba_script


def test_the_approval_key_file_is_protected(
    windows_script: str, samba_script: str
) -> None:
    """The key file is readable by SYSTEM, by Administrators and by the
    write account, and by nobody else."""
    assert "$ApprovalKeyPath = 'C:\\ProgramData\\Newton\\ad\\approval.key'" in (
        windows_script
    )
    assert "APPROVAL_KEY_PATH='/etc/newton-ad/approval.key'" in samba_script
    assert "chmod 0600" in samba_script


def test_the_key_is_written_as_64_lowercase_hex(
    windows_script: str, samba_script: str
) -> None:
    """The key file holds 64 lowercase hexadecimal characters and a
    newline."""
    assert "$keyHex + \"`n\"" in windows_script
    assert "stream.write(key.hex() + \"\\n\")" in samba_script


# ---- the login --------------------------------------------------------------


def test_the_windows_login_writes_the_key_and_the_sshd_block(
    windows_script: str,
) -> None:
    """The key file, its access control list and the sshd block."""
    assert (
        "$AuthorizedKeysPath = 'C:\\ProgramData\\Newton\\ad\\write_authorized_keys'"
        in windows_script
    )
    assert "'ReadAndExecute'" in windows_script
    assert "CN=OpenSSH Users,CN=Builtin," in windows_script
    assert "Add-ADGroupMember -Identity $openSshUsers -Members $OpsName" in (
        windows_script
    )
    assert "Match User $($netbios)\\$OpsName" in windows_script
    assert (
        "ForceCommand powershell.exe -NoProfile -NonInteractive "
        "-ExecutionPolicy Bypass -File C:\\ProgramData\\Newton\\ad\\write.ps1"
    ) in windows_script
    assert "PermitTTY no" in windows_script
    assert "AllowTcpForwarding no" in windows_script
    assert "PermitTunnel no" in windows_script
    assert "X11Forwarding no" in windows_script
    assert "AllowAgentForwarding no" in windows_script


def test_the_samba_login_writes_the_sudoers_line_last(samba_script: str) -> None:
    """The sudoers line is the last thing the script writes.

    A run that stops before it leaves no sudoers line behind, so a host
    that is not ready never lets the account run the write helper.
    """
    assert "LOGIN_NAME='newton-ops-ssh'" in samba_script
    assert (
        'SUDOERS_LINE=\'newton-ops-ssh ALL=(root) NOPASSWD: '
        '/usr/local/sbin/newton-ad-samba-write ""\''
    ) in samba_script
    assert "visudo -cf" in samba_script
    assert (
        'restrict,command="sudo -n /usr/local/sbin/newton-ad-samba-write" '
        "ssh-ed25519"
    ) in samba_script
    login = _step(samba_script, 6)
    assert login.index("visudo -cf") > login.index("authorized_keys")
    assert login.index("visudo -cf") > login.index("useradd")


def test_the_samba_keytab_is_made_and_proved(samba_script: str) -> None:
    """The keytab is made on every controller and it is proved."""
    assert "KEYTAB_PATH='/etc/newton-ad/ops.keytab'" in samba_script
    assert 'samba-tool domain exportkeytab "${KEYTAB_PATH}"' in samba_script
    assert "klist -k" in samba_script
    assert "kinit -k -t" in samba_script
    assert "mktemp -d /run/newton-ad-keytab.XXXXXX" in samba_script
    assert "chmod 0600" in samba_script
    # The script never writes an ops.secret.
    assert "ops.secret" not in samba_script


def test_the_sebatchlogonright_is_granted_on_the_pdc(windows_script: str) -> None:
    """The right is granted on the PDC only, through one GPO, and the
    holders of the right are kept."""
    assert DC_POLICY_GUID in windows_script
    assert "Backup-GPO -Guid $DefaultDcPolicyGuid" in windows_script
    assert "GptTmpl.inf" in windows_script
    assert "SeBatchLogonRight" in windows_script
    assert "gpupdate /target:computer /force" in windows_script
    assert "secedit /export /areas USER_RIGHTS" in windows_script
    assert "versionNumber" in windows_script
    assert "GPT.INI" in windows_script
    batch = _step(windows_script, 6)
    assert "if ($isPdc) {" in batch
    assert batch.index("if ($isPdc) {") < batch.index("gpupdate")


def test_the_inventory_entry_is_printed(
    windows_script: str, samba_script: str
) -> None:
    """The inventory entry names the platform, the domain, the host, the
    user and the key."""
    assert 'platform = "ad-windows-write"' in windows_script
    assert "('ad_domain = \"' + $DomainDevice + '\"')" in windows_script
    assert 'host = "' in windows_script
    assert 'user = "newton-ops@' in windows_script
    assert 'key_file = "' in windows_script
    assert 'platform = "ad-samba-write"' in samba_script
    assert 'ad_domain = "${DOMAIN_DEVICE}"' in samba_script
    assert 'user = "${LOGIN_NAME}"' in samba_script
    assert 'key_file = "' in samba_script
    # The path of the key of this controller is named too.
    assert "$AuthorizedKeysPath" in windows_script
    assert "${KEYFILE}" in samba_script
    # The placeholders the owner fills in are named as such.
    assert (
        "The key_file and known_hosts lines of the entry are placeholders "
        "the owner fills in."
    ) in windows_script
    assert (
        "The key_file and known_hosts lines of the entry are placeholders "
        "the owner fills in."
    ) in samba_script


def test_the_entry_prints_the_guid_of_the_domain_head(
    windows_script: str, samba_script: str, tmp_path: Path
) -> None:
    """The entry carries the objectGUID of the domain head, after ad_domain.

    The maq verb targets the domain head by that guid, and the plan
    refuses to build one when the inventory holds no guid for the head.
    The Windows script reads the guid with the same base read of the
    head that finds the role owner; the Samba script reads it with the
    same ldbsearch the pre-checks use.
    """
    assert (
        "-LDAPFilter '(objectClass=domainDNS)' -Properties fSMORoleOwner, objectGuid"
        in windows_script
    )
    assert 'Write-Host (\'ad_domain_guid = "\' + $DomainHeadGuid + \'"\')' in (
        windows_script
    )
    assert "ldif_value objectGUID" in samba_script
    assert 'ad_domain_guid = "${DOMAIN_GUID}"' in samba_script

    for lines in (
        _windows_entry_lines(windows_script, tmp_path),
        _samba_entry_lines(samba_script, tmp_path),
    ):
        block = _entry_block(lines)
        domain_at = next(
            index for index, line in enumerate(block)
            if line.startswith("ad_domain = ")
        )
        guid_at = next(
            index for index, line in enumerate(block)
            if line.startswith("ad_domain_guid = ")
        )
        assert guid_at == domain_at + 1


# ---- the domain device of the entry -------------------------------------------


_WIN_ASSIGNMENT_RE = re.compile(r"^\$(?:Device|Domain|DomainDevice|WriteHost|AuthorizedKeysPath) = '[^']*'$")
_SAMBA_ASSIGNMENT_RE = re.compile(r"^(?:DEVICE|DOMAIN|DOMAIN_DEVICE|WRITE_HOST|LOGIN_NAME|KEYFILE)='[^']*'$")


def _windows_entry_lines(script: str, tmp_path: Path) -> list[str]:
    """The lines the Windows script prints for the entry, run as they are."""
    program = "\n".join(
        [
            *[line for line in script.splitlines() if _WIN_ASSIGNMENT_RE.match(line)],
            _step(script, 7),
        ]
    )
    path = tmp_path / "win-entry.ps1"
    path.write_text(program, encoding="utf-8")
    result = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.splitlines()


def _samba_entry_lines(script: str, tmp_path: Path) -> list[str]:
    """The lines the Samba script prints for the entry, run as they are."""
    program = "\n".join(
        [
            *[line for line in script.splitlines() if _SAMBA_ASSIGNMENT_RE.match(line)],
            _step(script, 7),
        ]
    )
    path = tmp_path / "samba-entry.sh"
    path.write_text(program, encoding="utf-8")
    result = subprocess.run(
        ["bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.splitlines()


def _entry_block(lines: list[str]) -> list[str]:
    """The [devices.<name>] block of the printed lines, nothing else."""
    start = next(
        index for index, line in enumerate(lines) if line.startswith("[devices.")
    )
    block: list[str] = []
    for line in lines[start:]:
        if line.startswith("[") or re.match(r"^[a-z_]+ = ", line):
            block.append(line)
        else:
            break
    return block


def test_the_entry_prints_the_device_as_the_domain_device_by_default(
    windows_script: str, samba_script: str, tmp_path: Path
) -> None:
    """Without --domain-device the entry names its own device.

    The server refuses an ``ad_domain`` that is not an inventory name,
    so the entry may not print the DNS name of the domain there.
    """
    assert 'ad_domain = "windc1"' in _windows_entry_lines(windows_script, tmp_path)
    assert 'ad_domain = "sambadc1"' in _samba_entry_lines(samba_script, tmp_path)


def test_the_entry_prints_the_domain_device_of_the_argument(
    helpers: Path, tmp_path: Path
) -> None:
    """With --domain-device the entry names that device."""
    windows = write.windows_write_script(
        domain=DOMAIN,
        pubkey=write.validate_public_key(PUBLIC_KEY),
        device=DEVICE,
        host=HOST,
        ous=[OU],
        domain_device="dc1",
    )
    samba = write.samba_write_script(
        domain="lab.newton.test",
        pubkey=write.validate_public_key(PUBLIC_KEY),
        device="sambadc1",
        host="sambadc1.lab.newton.test",
        ous=["OU=Users,DC=lab,DC=newton,DC=test"],
        domain_device="dc1",
    )

    assert "$DomainDevice = 'dc1'" in windows
    assert "DOMAIN_DEVICE='dc1'" in samba
    assert 'ad_domain = "dc1"' in _windows_entry_lines(windows, tmp_path)
    assert 'ad_domain = "dc1"' in _samba_entry_lines(samba, tmp_path)


def test_both_entries_tell_the_owner_to_pass_the_domain_device(
    windows_script: str, samba_script: str, tmp_path: Path
) -> None:
    """Both scripts tell the owner how to set up the other DCs.

    The entry of a DC names the device that stands for the domain, and
    the owner of a DC that is not that device has to run the setup
    with --domain-device.  Both scripts say so.
    """
    hint = "On every other DC, run the setup with --domain-device <that name>."

    assert hint in "\n".join(_windows_entry_lines(windows_script, tmp_path))
    assert hint in "\n".join(_samba_entry_lines(samba_script, tmp_path))


def test_a_domain_device_outside_the_grammar_is_refused(
    helpers: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A --domain-device that is not an inventory name is refused.

    It is refused the way a bad --device is: the same pattern, the same
    error, the same exit code.
    """
    with pytest.raises(write.SetupError):
        write.windows_write_script(
            domain=DOMAIN,
            pubkey=write.validate_public_key(PUBLIC_KEY),
            device=DEVICE,
            host=HOST,
            ous=[OU],
            domain_device="Win.newton.test",
        )
    with pytest.raises(write.SetupError):
        write.samba_write_script(
            domain="lab.newton.test",
            pubkey=write.validate_public_key(PUBLIC_KEY),
            device="sambadc1",
            host="sambadc1.lab.newton.test",
            ous=["OU=Users,DC=lab,DC=newton,DC=test"],
            domain_device="Win.newton.test",
        )
    key = tmp_path / "write.pub"
    key.write_text(PUBLIC_KEY + "\n", encoding="utf-8")

    for platform in ("windows", "samba"):
        code = write.main(
            [
                "write",
                platform,
                "--domain",
                DOMAIN,
                "--pubkey",
                str(key),
                "--device",
                DEVICE,
                "--host",
                HOST,
                "--ou",
                OU,
                "--domain-device",
                "Win.newton.test",
            ]
        )

        assert code == 2
        assert "domain device" in capsys.readouterr().err


def test_the_printed_entries_load_through_the_inventory(
    windows_script: str,
    samba_script: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The entries the two scripts print are entries the server accepts.

    The placeholder lines are filled with the values of the other
    inventory tests, the guid of the domain head with a valid guid, and
    the entries go through the loader of the server, the one the MCP
    reads the inventory with.
    """
    key = tmp_path / "id_ed25519"
    key.write_text("synthetic\n", encoding="utf-8")
    key.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("192.0.2.10 ssh-ed25519 synthetic\n", encoding="utf-8")

    guids = {
        "[devices.windc1]": WIN_DOMAIN_GUID,
        "[devices.sambadc1]": SAMBA_DOMAIN_GUID,
    }
    blocks = []
    for lines in (
        _windows_entry_lines(windows_script, tmp_path),
        _samba_entry_lines(samba_script, tmp_path),
    ):
        filled = []
        header = next(line for line in _entry_block(lines) if line.startswith("["))
        for line in _entry_block(lines):
            if line.startswith("key_file"):
                line = f'key_file = "{key}"'
            elif line.startswith("known_hosts"):
                line = f'known_hosts = "{known_hosts}"'
            elif line.startswith("ad_domain_guid"):
                line = f'ad_domain_guid = "{guids[header]}"'
            filled.append(line)
        blocks.append("\n".join(filled))
    path = tmp_path / "devices.toml"
    path.write_text("\n".join(blocks) + "\n", encoding="utf-8")
    path.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(path))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    devices = load_inventory()

    assert devices["windc1"].ad_domain == "windc1"
    assert devices["sambadc1"].ad_domain == "sambadc1"
    assert devices["windc1"].ad_domain_guid == WIN_DOMAIN_GUID
    assert devices["sambadc1"].ad_domain_guid == SAMBA_DOMAIN_GUID
    assert inventory.domain_guid(devices, "windc1") == WIN_DOMAIN_GUID
    assert inventory.domain_guid(devices, "sambadc1") == SAMBA_DOMAIN_GUID


# ---- the grammars -----------------------------------------------------------


@pytest.mark.parametrize(
    "ou",
    [
        "OU=Users,DC=win,DC=newton,DC=test",
        "CN=Users,DC=win,DC=newton,DC=test",
        "OU=Staff,OU=Users,DC=win,DC=newton,DC=test",
        "OU=Staff,OU=Users,DC=WIN,DC=NEWTON,DC=TEST",
    ],
)
def test_a_delegated_location_inside_the_domain_is_accepted(ou: str) -> None:
    """A location inside the domain is delegated."""
    assert write.validate_ou(ou, DOMAIN) == ou


@pytest.mark.parametrize(
    "ou",
    [
        "",
        "Users",
        "OU=Users",
        "OU=Users,DC=other,DC=newton,DC=test",
        "OU=Users,DC=win,DC=newton",
        "OU=Users,DC=win,DC=newton,DC=test,DC=extra",
        "XX=Users,DC=win,DC=newton,DC=test",
        "OU=Users,DC=win,DC=newton,DC=test;whoami",
        "OU=Us'ers,DC=win,DC=newton,DC=test",
        "OU=Us$ers,DC=win,DC=newton,DC=test",
        "OU=Users,DC=win,DC=newton,DC=test\n",
        "OU=Us`ers,DC=win,DC=newton,DC=test",
        "OU=Us\\ers,DC=win,DC=newton,DC=test",
        "OU=Us<ers,DC=win,DC=newton,DC=test",
    ],
)
def test_a_delegated_location_outside_the_grammar_is_refused(ou: str) -> None:
    """A location that is not a name inside the domain is refused."""
    with pytest.raises(write.SetupError):
        write.validate_ou(ou, DOMAIN)


def test_the_head_of_the_domain_is_refused() -> None:
    """The head of the domain is not a delegated location."""
    with pytest.raises(write.SetupError) as refusal:
        write.validate_ou(DOMAIN_DN, DOMAIN)
    assert "head of the domain" in str(refusal.value)


def test_the_ou_of_the_domain_controllers_is_refused() -> None:
    """The OU of the domain controllers is not a delegated location.

    A write on the computer objects of that OU is a write on the
    account of a domain controller.
    """
    with pytest.raises(write.SetupError) as refusal:
        write.validate_ou(f"OU=Domain Controllers,{DOMAIN_DN}", DOMAIN)
    assert "domain controllers" in str(refusal.value)


def test_the_same_location_twice_is_refused() -> None:
    """The same location is named once."""
    with pytest.raises(write.SetupError):
        write.validate_ous([OU, OU], DOMAIN)


def test_a_run_without_a_location_is_refused() -> None:
    """At least one location is needed."""
    with pytest.raises(write.SetupError):
        write.validate_ous([], DOMAIN)


# ---- the approval key on this host ------------------------------------------


def test_the_approval_key_stores_only_the_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The file holds the fingerprint of the key and nothing else."""
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(write, "_getpass", lambda prompt: PASSPHRASE)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=True)

    code = write.main(["approval-key", DEVICE])

    assert code == 0
    key = approve.derive_k(PASSPHRASE.encode("utf-8"), DEVICE)
    fingerprint = approve.approval_fingerprint(key)
    assert capsys.readouterr().out.strip() == fingerprint
    path = tmp_path / "state" / "approval-fp" / DEVICE
    assert path.read_text(encoding="ascii") == f"v1 {fingerprint}\n"
    assert key not in path.read_text(encoding="ascii")
    assert PASSPHRASE not in path.read_text(encoding="ascii")
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_the_approval_key_refuses_an_empty_passphrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty passphrase is a refusal and nothing is written."""
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(write, "_getpass", lambda prompt: "")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=True)

    code = write.main(["approval-key", DEVICE])

    assert code == 2
    assert "must not be empty" in capsys.readouterr().err
    assert not (tmp_path / "state" / "approval-fp" / DEVICE).exists()


def test_the_approval_key_refuses_two_different_passphrases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two different passphrases are a refusal and nothing is written."""
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    answers = iter([PASSPHRASE, PASSPHRASE + " other"])
    monkeypatch.setattr(write, "_getpass", lambda prompt: next(answers))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=True)

    code = write.main(["approval-key", DEVICE])

    assert code == 2
    assert "do not match" in capsys.readouterr().err
    assert not (tmp_path / "state" / "approval-fp" / DEVICE).exists()


def test_the_approval_key_refuses_a_device_that_is_not_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The device name is the name of an inventory device."""
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    code = write.main(["approval-key", "Wind DC1"])

    assert code == 2
    assert "device name" in capsys.readouterr().err


def test_the_approval_key_refuses_a_stdin_that_is_not_a_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The passphrase is read from a terminal, never from a pipe."""
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=True)

    code = write.main(["approval-key", DEVICE])

    assert code == 2
    assert "terminal" in capsys.readouterr().err
    assert not (tmp_path / "state" / "approval-fp" / DEVICE).exists()


# ---- the key parity ---------------------------------------------------------


def _pwsh() -> str:
    """The PowerShell of this machine, when it is there."""
    if PWSH.exists():
        return str(PWSH)
    found = shutil.which("pwsh")
    if found:
        return found
    pytest.skip("pwsh is not on this machine")


def test_the_powershell_code_derives_the_same_key(
    windows_script: str, tmp_path: Path
) -> None:
    """The PowerShell of the script derives the key of ``derive_k``.

    The passphrase and the device are fixed, so the key and the
    fingerprint are the ones of the Newton host.
    """
    program = "\n".join(
        [
            _powershell_function(windows_script, "Get-ApprovalKeyHex"),
            _powershell_function(windows_script, "Get-ApprovalFingerprintHex"),
            f"$key = Get-ApprovalKeyHex '{PASSPHRASE}' '{DEVICE}'",
            "Write-Output $key",
            "Write-Output (Get-ApprovalFingerprintHex $key)",
        ]
    )
    path = tmp_path / "key.ps1"
    path.write_text(program, encoding="utf-8")

    result = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    key = approve.derive_k(PASSPHRASE.encode("utf-8"), DEVICE)
    fingerprint = approve.approval_fingerprint(key)
    assert result.stdout.split() == [key, fingerprint]


def test_the_python_code_derives_the_same_key(samba_script: str) -> None:
    """The Python of the script derives the key of ``derive_k``."""
    namespace: dict[str, object] = {"__name__": "newton_approval"}
    source = _embedded_python(samba_script, "approval.py")
    exec(compile(source, "approval.py", "exec"), namespace)

    key = namespace["derive"](PASSPHRASE, DEVICE)  # type: ignore[operator]
    fingerprint = namespace["fingerprint"](key)  # type: ignore[operator]

    assert key.hex() == approve.derive_k(PASSPHRASE.encode("utf-8"), DEVICE)
    assert fingerprint == approve.approval_fingerprint(key.hex())


def test_the_two_scripts_ask_the_passphrase_twice(
    windows_script: str, samba_script: str
) -> None:
    """The passphrase is asked twice on the controller, without echo."""
    assert "Read-Host -AsSecureString" in windows_script
    assert windows_script.count("Read-Host -AsSecureString") == 2
    assert "getpass.getpass" in samba_script
    assert samba_script.count("getpass.getpass") == 2
    assert "the approval passphrase must not be empty" in windows_script
    assert "the two approval passphrases do not match" in windows_script
    assert "the approval passphrase must not be empty" in samba_script
    assert "the two approval passphrases do not match" in samba_script


def test_the_marshalled_string_of_the_passphrase_is_cleared(
    windows_script: str,
) -> None:
    """The BSTR of the passphrase is freed right after it is read."""
    assert "SecureStringToBSTR" in windows_script
    assert "ZeroFreeBSTR" in windows_script
    assert windows_script.count("ZeroFreeBSTR") == 2


# ---- the command line -------------------------------------------------------


def test_the_command_prints_the_windows_script(
    tmp_path: Path, helpers: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The write command prints the Windows script."""
    key = tmp_path / "write.pub"
    key.write_text(PUBLIC_KEY + "\n", encoding="utf-8")

    code = write.main(
        [
            "write",
            "windows",
            "--domain",
            DOMAIN,
            "--pubkey",
            str(key),
            "--device",
            DEVICE,
            "--host",
            HOST,
            "--ou",
            OU,
        ]
    )

    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("# Newton's Active Directory write setup (Windows).")


def test_the_command_prints_the_samba_script(
    tmp_path: Path, helpers: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The write command prints the Samba script."""
    key = tmp_path / "write.pub"
    key.write_text(PUBLIC_KEY + "\n", encoding="utf-8")

    code = write.main(
        [
            "write",
            "samba",
            "--domain",
            "lab.newton.test",
            "--pubkey",
            str(key),
            "--device",
            "sambadc1",
            "--host",
            "sambadc1.lab.newton.test",
            "--ou",
            "OU=Users,DC=lab,DC=newton,DC=test",
        ]
    )

    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("#!/usr/bin/env bash\n")


def test_the_command_refuses_a_location_outside_the_domain(
    tmp_path: Path, helpers: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A location that is not inside the domain is refused."""
    key = tmp_path / "write.pub"
    key.write_text(PUBLIC_KEY + "\n", encoding="utf-8")

    code = write.main(
        [
            "write",
            "windows",
            "--domain",
            DOMAIN,
            "--pubkey",
            str(key),
            "--device",
            DEVICE,
            "--host",
            HOST,
            "--ou",
            DOMAIN_DN,
        ]
    )

    assert code == 2
    assert "head of the domain" in capsys.readouterr().err


def test_the_command_refuses_a_build_without_the_write_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A build without the write helper says so and installs nothing."""
    monkeypatch.setattr(
        write, "WRITE_HELPER_PATH", tmp_path / "there-is-no-helper.ps1"
    )
    key = tmp_path / "write.pub"
    key.write_text(PUBLIC_KEY + "\n", encoding="utf-8")

    code = write.main(
        [
            "write",
            "windows",
            "--domain",
            DOMAIN,
            "--pubkey",
            str(key),
            "--device",
            DEVICE,
            "--host",
            HOST,
            "--ou",
            OU,
        ]
    )

    assert code == 2
    assert "the write helper is not in this build" in capsys.readouterr().err


def test_the_wrapper_routes_the_write_command(
    tmp_path: Path, helpers: Path
) -> None:
    """The wrapper in scripts/ hands the write command to the write module."""
    key = tmp_path / "write.pub"
    key.write_text(PUBLIC_KEY + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            str(SCRIPT),
            "write",
            "windows",
            "--domain",
            DOMAIN,
            "--pubkey",
            str(key),
            "--device",
            DEVICE,
            "--host",
            HOST,
            "--ou",
            OU,
        ],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )

    assert result.returncode == 0
    assert result.stdout.startswith(
        "# Newton's Active Directory write setup (Windows)."
    )


# ---- the scripts themselves -------------------------------------------------


def test_the_samba_script_is_valid_bash(tmp_path: Path, samba_script: str) -> None:
    """The script is written out and bash parses it."""
    if shutil.which("bash") is None:
        pytest.skip("bash is not on this machine")
    path = tmp_path / "newton-ad-write-setup.sh"
    path.write_text(samba_script, encoding="utf-8")

    result = subprocess.run(
        ["bash", "-n", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_the_windows_script_parses(tmp_path: Path, windows_script: str) -> None:
    """The script is written out and PowerShell parses it."""
    path = tmp_path / "newton-ad-write-setup.ps1"
    path.write_text(windows_script, encoding="utf-8")

    program = (
        "$errors = $null; $tokens = $null; "
        "$ast = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{path}', [ref]$tokens, [ref]$errors); "
        "if ($errors.Count -gt 0) { $errors | ForEach-Object { $_.Message }; exit 1 }"
    )
    result = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_the_embedded_python_of_the_samba_script_parses(samba_script: str) -> None:
    """The two programs the Samba script writes are valid Python."""
    for name in ("approval.py", "ad_write_setup.py"):
        source = _embedded_python(samba_script, name)
        compile(source, name, "exec")


# ---- the skill --------------------------------------------------------------


def test_skill_md_says_every_dc_takes_the_same_passphrase() -> None:
    """The owner types the same passphrase on every DC of the domain.

    The key of the approval is derived from the passphrase and from the
    name of the domain device, so a DC that was set up with another
    passphrase holds another key and refuses every change of the
    domain.  The skill says so, on one line, and the line is not
    wrapped: the owner reads it as it is printed.
    """
    text = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")

    assert "same approval passphrase on every DC" in text
    assert any(
        "same approval passphrase on every DC" in line
        for line in text.splitlines()
    )
