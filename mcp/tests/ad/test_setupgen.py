"""The owner's setup script for an AD collector host.

The script is printed, never run: the owner reads it and runs it as a
Domain Admin on the domain controller.  The tests here read the printed
script and check that it carries every step, that it carries no
password and no private key, and that the blobs it embeds are the
package files themselves.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import fake_setup
from newton_mcp.ad import forbidden, setupgen


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "newton-ad-setup"


def _key_body(key_type: str) -> str:
    """The base64 body of a synthetic public key of one type.

    The body of an OpenSSH public key is a sequence of length-prefixed
    fields and the first one is the type of the key, so a synthetic body
    carries its type the way a real one does.  The key material itself
    is synthetic: the lab key is never read by a test.
    """
    payload = key_type.encode("ascii")
    blob = len(payload).to_bytes(4, "big") + payload + bytes(32)
    return base64.b64encode(blob).decode("ascii")


KEY_BODY = _key_body("ssh-ed25519")
RSA_BODY = _key_body("ssh-rsa")
PUBLIC_KEY = f"ssh-ed25519 {KEY_BODY}\n"


@pytest.fixture
def pubkey(tmp_path: Path) -> Path:
    """A synthetic public key file."""
    path = tmp_path / "audit.pub"
    path.write_text(PUBLIC_KEY, encoding="utf-8")
    return path


@pytest.fixture
def script(pubkey: Path) -> str:
    """The printed Windows setup script."""
    return setupgen.windows_script(
        domain="win.newton.test",
        pubkey=setupgen.validate_public_key(PUBLIC_KEY),
        device="windc1",
        host="192.0.2.31",
    )


def _blob(script: str, name: str) -> bytes:
    """The bytes of one base64 blob of the script."""
    lines = script.splitlines()
    start = lines.index(f"${name} = @(")
    chunks: list[str] = []
    for line in lines[start + 1 :]:
        if line == ")":
            break
        chunks.append(line.strip().strip("'"))
    return base64.b64decode("".join(chunks))


def test_the_script_holds_every_step(script: str) -> None:
    """The seven steps are in the script, in the order of the spec."""
    steps = [
        "Step 1: the newton-audit account",
        "Step 2: the collector files",
        "Step 3: the access control list",
        "Step 4: the authorized key",
        "Step 5: the sshd configuration",
        "Step 6: the sshd restart",
        "Step 7: the inventory entry",
    ]
    places = [script.index(step) for step in steps]
    assert places == sorted(places)


def test_the_script_is_one_script_that_parses(tmp_path: Path, script: str) -> None:
    """The generated script is written out and holds no stray quote.

    The script is one PowerShell script: no here-string and no literal
    that is left open at the end of its line.  The owner runs it as it
    is, so a stray quote is a script that stops halfway.
    """
    path = tmp_path / "newton-ad-setup.ps1"
    path.write_text(script, encoding="utf-8")

    assert path.read_text(encoding="utf-8") == script
    assert '@"' not in script
    assert '"@' not in script
    for number, line in enumerate(script.splitlines(), start=1):
        if line.strip().startswith("#"):
            continue
        assert line.count("'") % 2 == 0, f"line {number} has a stray quote: {line}"


def test_the_script_creates_the_account_and_its_group(script: str) -> None:
    """The account is a domain user and is in the OpenSSH Users group."""
    assert "New-ADUser -Name $AuditName" in script
    assert "-PrimaryGroupID" not in script
    assert (
        "Get-ADGroup -Identity ('CN=OpenSSH Users,CN=Builtin,' "
        "+ (Get-ADDomain).DistinguishedName)"
    ) in script
    assert "Add-ADGroupMember -Identity $openSshUsers -Members $AuditName" in script
    assert "New-Object 'System.Byte[]' 32" in script


def test_the_script_looks_the_account_up_without_throwing(script: str) -> None:
    """A missing account is found by a filter, never by an identity.

    ``Get-ADUser -Identity`` throws when the account does not exist and
    the error is not one that ``-ErrorAction SilentlyContinue`` swallows,
    so the script died on the first run of a fresh domain.  A filter
    answers with nothing and never throws.
    """
    assert (
        "$user = Get-ADUser -Filter \"SamAccountName -eq '$AuditName'\""
    ) in script
    assert "Get-ADUser -Identity" not in script


def test_the_script_reads_the_groups_of_the_account_the_way_the_module_adds_them(
    script: str,
) -> None:
    """The groups are read from the account, not from its property collection.

    A live rerun on the lab DC (WINDC1) died in step 1 with "The
    property 'memberOf' cannot be found on this object": the script read
    the groups through the ``.Properties`` collection of the account, and
    that collection holds no property of that name.  The module adds the
    property that ``-Properties`` asks for to the account itself, so the
    account is where it is read from.
    """
    assert "-Properties MemberOf).MemberOf" in script
    assert ".Properties.memberOf" not in script


def test_the_script_reads_no_property_of_a_directory_object_that_may_be_absent(
    script: str,
) -> None:
    """No step reads a property of a directory object that may not be there.

    The script runs under ``Set-StrictMode -Version 3``, where reading a
    property that is not there stops the script.  Every property of an
    Active Directory object that the script reads is either a default
    property of the object or one the script asked for with
    ``-Properties``.
    """
    assert ".Properties." not in script
    assert ".SamAccountName" not in script


def test_the_script_tests_the_membership_without_reading_a_property_that_may_be_absent(
    script: str,
) -> None:
    """The membership is tested with a property read that cannot throw.

    ``Get-ADGroupMember`` answers with objects of the type of the
    member, and a member that is not a user has no ``SamAccountName``:
    reading it under StrictMode 3 stops the script.  The property is
    looked up in the object itself, so a member that does not carry it
    is not a match and the script goes on.
    """
    assert "$member.PSObject.Properties['SamAccountName']" in script
    assert ".SamAccountName" not in script


def test_the_script_never_writes_a_password_down(script: str) -> None:
    """The password is generated inside the script and never shown."""
    assert "$password = [Convert]::ToBase64String($random)" in script
    assert "-AccountPassword $secure" in script
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("$password"):
            assert "'" not in stripped
            assert '"' not in stripped


def test_the_script_embeds_no_private_key(script: str) -> None:
    """Only the public key of the audit key is in the script."""
    assert f"restrict ssh-ed25519 {KEY_BODY}" in script
    assert "PRIVATE KEY" not in script
    assert "BEGIN OPENSSH" not in script


def test_the_blobs_are_the_package_files(script: str) -> None:
    """The three blobs decode to the files the package ships."""
    assert _blob(script, "collectorB64") == setupgen.COLLECTOR_PATH.read_bytes()
    assert _blob(script, "queriesB64") == setupgen.QUERIES_PATH.read_bytes()
    assert _blob(script, "forbiddenB64") == forbidden.dump_json()


def test_the_script_carries_the_hash_of_every_file(script: str) -> None:
    """The script checks every file against the hash of the package."""
    for name, data in (
        ("collector.ps1", setupgen.COLLECTOR_PATH.read_bytes()),
        ("queries.json", setupgen.QUERIES_PATH.read_bytes()),
        ("forbidden.json", forbidden.dump_json()),
    ):
        assert hashlib.sha256(data).hexdigest() in script
    assert "Get-FileHash -Algorithm SHA256" in script


def test_the_script_grants_the_acl_by_sid(script: str) -> None:
    """The grants are by SID object and never by name."""
    assert "System.Security.Principal.SecurityIdentifier('S-1-5-32-544')" in script
    assert "System.Security.Principal.SecurityIdentifier('S-1-5-18')" in script
    assert (
        "$auditUser = @(Get-ADUser -Filter \"SamAccountName -eq '$AuditName'\")"
    ) in script
    assert "$auditSid = $auditUser[0].SID" in script
    assert "SetAccessRuleProtection($true, $false)" in script
    assert "'FullControl'" in script
    assert "'ReadAndExecute'" in script
    assert "BUILTIN\\Administrators" not in script


def test_the_script_sets_the_owner_before_the_acl(script: str) -> None:
    """The owner of the directory is Administrators, set before the ACL."""
    assert "$acl.SetOwner($administrators)" in script
    assert script.index("$acl.SetOwner($administrators)") < script.index(
        "Set-Acl -LiteralPath $entry.path"
    )


def test_the_script_writes_the_sshd_block_once(script: str) -> None:
    """The block is appended once and the configuration is put back on failure."""
    assert "sshd_config.bak-newton" in script
    assert "Match User $($netbios)\\newton-audit" in script
    assert "AuthorizedKeysFile __PROGRAMDATA__/Newton/ad/authorized_keys" in script
    assert (
        "ForceCommand powershell.exe -NoProfile -NonInteractive "
        "-ExecutionPolicy Bypass -File C:\\ProgramData\\Newton\\ad\\collector.ps1"
    ) in script
    assert "PermitTTY no" in script
    assert "AllowTcpForwarding no" in script
    assert "X11Forwarding no" in script
    assert "$blockLines = @(" in script


def test_the_script_finds_sshd_and_validates_the_configuration(script: str) -> None:
    """sshd.exe is found and the configuration it refuses is restored."""
    assert "Get-Command sshd.exe -ErrorAction SilentlyContinue" in script
    assert "System32\\OpenSSH\\sshd.exe" in script
    assert "OpenSSH\\sshd.exe" in script
    assert "& $sshdExe -t" in script
    assert "$sshdExit = $LASTEXITCODE" in script
    assert "if ($sshdExit -ne 0) {" in script
    assert "sshd.exe was not found" in script


def test_the_script_restores_the_config_it_read_and_not_the_first_backup(
    script: str,
) -> None:
    """A refused configuration is put back the way it was read.

    The one-time ``.bak-newton`` is the first-ever backup of the file:
    restoring it would drop every change the owner made after the first
    run.  The config read just before the append is what goes back.
    """
    restore = (
        "[System.IO.File]::WriteAllText($SshdConfig, $config, "
        "(New-Object System.Text.UTF8Encoding($false)))"
    )
    assert restore in script
    assert (
        "Copy-Item -LiteralPath $SshdBackup -Destination $SshdConfig -Force"
        not in script
    )
    assert "Copy-Item -LiteralPath $SshdConfig -Destination $SshdBackup -Force" in script


def test_the_script_restarts_sshd_through_a_system_task(script: str) -> None:
    """The restart is a one-shot SYSTEM task eight seconds later."""
    assert "Unregister-ScheduledTask -TaskName $RestartTask" in script
    assert "New-ScheduledTaskPrincipal -UserId 'SYSTEM'" in script
    assert "AddSeconds(8)" in script
    assert "Restart-Service sshd -Force" in script


def test_the_script_restarts_sshd_only_when_the_configuration_changed(
    script: str,
) -> None:
    """A rerun on an unchanged configuration restarts nothing.

    The task of an earlier run is removed either way, so a rerun leaves
    no task behind.
    """
    assert "$sshdChanged = $false" in script
    assert "$sshdChanged = $true" in script
    assert "if ($sshdChanged) {" in script
    assert script.index("Unregister-ScheduledTask -TaskName $RestartTask") < script.index(
        "if ($sshdChanged) {"
    )
    assert script.index("if ($sshdChanged) {") < script.index(
        "Register-ScheduledTask -TaskName $RestartTask"
    )


def test_the_script_prints_the_inventory_entry(script: str) -> None:
    """The inventory entry names the platform, the host, the user and the key."""
    assert "platform = \"ad-windows\"" in script
    assert "'host = \"' + $CollectorHost + '\"'" in script
    assert "'user = \"newton-audit@' + $Domain + '\"'" in script
    assert "'domain = \"' + $Domain + '\"'" in script
    assert "key_file = " in script
    assert "known_hosts = " in script


def test_the_validator_accepts_the_two_key_types() -> None:
    """An ed25519 key and an rsa key are accepted."""
    ed25519 = setupgen.validate_public_key(f"ssh-ed25519 {KEY_BODY}")
    rsa = setupgen.validate_public_key(f"ssh-rsa {RSA_BODY}")
    assert ed25519 == f"ssh-ed25519 {KEY_BODY}"
    assert rsa == f"ssh-rsa {RSA_BODY}"


def test_the_validator_accepts_the_shape_of_the_audit_key() -> None:
    """A key with a comment is accepted and the comment is dropped.

    The audit key of the lab is one line of three fields:
    ``ssh-ed25519 <body> <comment>``.  The comment is not part of the
    key, so it never reaches the authorized_keys file.
    """
    line = f"ssh-ed25519 {KEY_BODY} newton-audit-lab"

    assert setupgen.validate_public_key(line) == f"ssh-ed25519 {KEY_BODY}"
    assert setupgen.validate_public_key(line + "\n") == f"ssh-ed25519 {KEY_BODY}"


@pytest.mark.parametrize(
    "text",
    [
        'command="C:\\x" ssh-ed25519 AAAA',
        'no-pty,no-port-forwarding ssh-ed25519 AAAA',
        "ssh-ed25519 AAAA extra",
        "ssh-dss AAAAB3NzaC1kc3M=",
        "ecdsa-sha2-nistp256 AAAAE2VjZHNh",
        "ssh-ed25519 not base64!",
        f"ssh-ed25519 {KEY_BODY}\nssh-ed25519 {KEY_BODY}",
        f"ssh-ed25519 {KEY_BODY}\r\nssh-rsa {RSA_BODY}",
        f"ssh-rsa {KEY_BODY}",
        f"ssh-ed25519 {RSA_BODY}",
        "ssh-ed25519",
    ],
)
def test_the_validator_refuses_everything_else(text: str) -> None:
    """Options, a second line, another key type and a wrong body are refused."""
    with pytest.raises(setupgen.SetupError):
        setupgen.validate_public_key(text)


def test_the_validator_accepts_one_line_with_a_trailing_newline() -> None:
    """The normal end of a key file is accepted."""
    assert setupgen.validate_public_key(PUBLIC_KEY) == f"ssh-ed25519 {KEY_BODY}"


def test_the_windows_build_prints_the_script(
    pubkey: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The windows build prints the script and says nothing else."""
    code = setupgen.main(
        [
            "windows",
            "--domain",
            "win.newton.test",
            "--pubkey",
            str(pubkey),
            "--device",
            "windc1",
            "--host",
            "192.0.2.31",
        ]
    )

    assert code == 0
    out = capsys.readouterr()
    assert out.err == ""
    assert out.out.startswith("# Newton's Active Directory collector setup.")


def test_the_samba_build_prints_its_script(
    pubkey: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The samba build prints the bash script and says nothing else."""
    code = setupgen.main(
        [
            "samba",
            "--domain",
            "lab.newton.test",
            "--pubkey",
            str(pubkey),
            "--device",
            "sambadc",
            "--host",
            "192.0.2.21",
        ]
    )

    assert code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("#!/usr/bin/env bash\n")
    assert (
        "# Newton's Active Directory collector setup (Samba)." in captured.out
    )


def test_a_bad_public_key_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key file with two lines is refused."""
    path = tmp_path / "audit.pub"
    path.write_text(PUBLIC_KEY * 2, encoding="utf-8")

    code = setupgen.main(
        [
            "windows",
            "--domain",
            "win.newton.test",
            "--pubkey",
            str(path),
            "--device",
            "windc1",
            "--host",
            "192.0.2.31",
        ]
    )

    assert code == 2
    assert "exactly one key line" in capsys.readouterr().err


def test_the_script_refuses_a_host_that_is_not_a_host(
    pubkey: Path,
) -> None:
    """A host outside the grammar is refused."""
    with pytest.raises(setupgen.SetupError):
        setupgen.windows_script(
            domain="win.newton.test",
            pubkey="ssh-ed25519 AAAA",
            device="windc1",
            host="a host",
        )


def test_the_command_line_tool_prints_the_script(pubkey: Path) -> None:
    """The wrapper in scripts/ prints the same script."""
    result = subprocess.run(
        [
            str(SCRIPT),
            "windows",
            "--domain",
            "win.newton.test",
            "--pubkey",
            str(pubkey),
            "--device",
            "windc1",
            "--host",
            "192.0.2.31",
        ],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("# Newton's Active Directory collector setup.")


def test_the_command_line_tool_prints_the_samba_script(pubkey: Path) -> None:
    """The wrapper prints the samba script."""
    result = subprocess.run(
        [
            str(SCRIPT),
            "samba",
            "--domain",
            "lab.newton.test",
            "--pubkey",
            str(pubkey),
            "--device",
            "sambadc",
            "--host",
            "192.0.2.21",
        ],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("#!/usr/bin/env bash\n")
    assert (
        "# Newton's Active Directory collector setup (Samba)." in result.stdout
    )


def test_the_module_runs_as_a_program(pubkey: Path) -> None:
    """The module is runnable with -m."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "newton_mcp.ad.setupgen",
            "windows",
            "--domain",
            "win.newton.test",
            "--pubkey",
            str(pubkey),
            "--device",
            "windc1",
            "--host",
            "192.0.2.31",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT / "mcp"),
    )

    assert result.returncode == 0, result.stderr
    assert "Step 7: the inventory entry" in result.stdout


# ---- the Samba script -------------------------------------------------------


@pytest.fixture
def samba_script() -> str:
    """The printed Samba setup script."""
    return setupgen.samba_script(
        domain="lab.newton.test",
        pubkey=setupgen.validate_public_key(PUBLIC_KEY),
        device="sambadc",
        host="192.0.2.21",
    )


def _samba_blob(script: str, name: str) -> bytes:
    """The bytes of one base64 blob of the Samba script."""
    lines = script.splitlines()
    start = lines.index(
        f'cat > "${{WORK_DIR}}/{name}.b64" <<\'NEWTON_AD_BLOB_EOF\''
    )
    chunks: list[str] = []
    for line in lines[start + 1 :]:
        if line == "NEWTON_AD_BLOB_EOF":
            break
        chunks.append(line)
    return base64.b64decode("".join(chunks))


def test_the_samba_script_holds_every_step(samba_script: str) -> None:
    """The steps of the script are in it, in the order of the spec."""
    steps = [
        "Step 1: the newton-audit domain account",
        "Step 2: the local newton-ssh account",
        "Step 3: the directories of the install",
        "Step 4: the collector files",
        "Step 5: the authorized key",
        "Step 6: the sudoers line",
        "Step 7: the inventory entry",
    ]
    places = [samba_script.index(step) for step in steps]
    assert places == sorted(places)


def test_the_samba_script_writes_the_sudoers_line_last(samba_script: str) -> None:
    """The sudoers line is the last thing the script writes.

    A run that stops before it leaves no sudoers file behind, so a host
    that is not ready never lets the account run the collector.
    """
    steps = [
        "Step 1: the newton-audit domain account",
        "Step 2: the local newton-ssh account",
        "Step 3: the directories of the install",
        "Step 4: the collector files",
        "Step 5: the authorized key",
        "Step 6: the sudoers line",
    ]
    places = [samba_script.index(step) for step in steps]
    assert places == sorted(places)
    # The line is written after every other file of the script.
    assert samba_script.index("SUDOERS_FILE") < samba_script.index(
        "visudo -cf \"${SUDOERS_FILE}\""
    )


def test_the_samba_script_is_valid_bash(tmp_path: Path, samba_script: str) -> None:
    """The script is written out and bash parses it.

    The owner runs the script as it is, so a syntax error is a script
    that stops halfway.
    """
    if shutil.which("bash") is None:
        pytest.skip("bash is not on this machine")
    path = tmp_path / "newton-ad-setup.sh"
    path.write_text(samba_script, encoding="utf-8")

    result = subprocess.run(
        ["bash", "-n", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_the_samba_script_creates_the_domain_account(samba_script: str) -> None:
    """The domain account is created with a random password.

    The account is looked up with ``samba-tool user show``: the names
    of ``samba-tool user list`` are bare, one per line, and a grep for
    a colon in them never matches.
    """
    assert 'samba-tool user create "${AUDIT_NAME}" --random-password' in samba_script
    assert "samba-tool user show newton-audit >/dev/null 2>&1" in samba_script
    assert "user list" not in samba_script


def test_the_samba_script_never_changes_a_membership(samba_script: str) -> None:
    """The membership of the account is never changed.

    The tool that would add a group to a user does not exist in
    samba-tool, and the primary group of a new account is Domain
    Users anyway: the account is not a member of it.
    """
    assert "addgroup" not in samba_script
    assert "samba-tool user add" not in samba_script


def test_the_samba_script_checks_the_primary_group_of_the_domain_account(
    samba_script: str,
) -> None:
    """The primary group is checked, and the script stops when it is not
    Domain Users."""
    assert "primaryGroupID" in samba_script
    assert "primaryGroupID: 513" in samba_script
    assert (
        "newton-audit's primary group is not Domain Users; "
        "fix it before running this again"
    ) in samba_script


def test_the_samba_script_creates_the_local_account_without_a_password(
    samba_script: str,
) -> None:
    """The local account is newton-ssh, with no password and a home of
    its own."""
    assert (
        "useradd --home-dir /var/lib/newton-ssh --shell /bin/sh "
        "--password '!' newton-ssh"
    ) in samba_script
    assert "getent -s files passwd newton-ssh" in samba_script
    assert "HOME_DIR='/var/lib/newton-ssh'" in samba_script
    assert "KEYFILE='/var/lib/newton-ssh/.ssh/authorized_keys'" in samba_script


def test_the_samba_script_never_asks_the_identification_of_the_account(
    samba_script: str,
) -> None:
    """The local account is looked up with getent and never with id.

    The domain account resolves locally, so ``id`` would answer for an
    account that is not there and the script would never create the
    local one.
    """
    assert "id -u" not in samba_script
    assert "id -uG" not in samba_script


def test_the_samba_script_explains_the_two_names(samba_script: str) -> None:
    """The script says why the login account and the domain account have
    different names."""
    assert "winbind" in samba_script
    assert "/bin/false" in samba_script
    assert "already exists" in samba_script


def test_the_samba_script_writes_the_authorized_key(samba_script: str) -> None:
    """The one key line forces the collector and nothing else.

    The "restrict" option of OpenSSH turns every other restriction off
    at once, so the line carries it and not the options one by one.

    The key belongs to root: sshd reads it as root, and StrictModes
    accepts a file of the home of the account that root owns as long
    as neither its group nor the others may write it.
    """
    assert (
        'KEY_LINE=\'restrict,command="sudo -n /usr/local/sbin/newton-ad-samba" '
        f"ssh-ed25519 {KEY_BODY}'" in samba_script
    )
    assert 'install -m 0644 -o root -g root' in samba_script
    assert "chmod 0755" in samba_script
    assert 'chown root:root "${HOME_DIR}" "${HOME_DIR}/.ssh"' in samba_script


def test_the_samba_script_writes_the_sudoers_line(samba_script: str) -> None:
    """The one sudoers line is exactly the line of the spec, and visudo
    checks it.

    The empty argument is what allows the collector to run with no
    argument at all.
    """
    assert (
        "SUDOERS_LINE='newton-ssh ALL=(root) NOPASSWD: "
        '/usr/local/sbin/newton-ad-samba ""\'' in samba_script
    )
    assert "SUDOERS_FILE='/etc/sudoers.d/newton-ssh'" in samba_script
    assert "visudo -cf" in samba_script
    assert "chmod 0440" in samba_script
    assert "chown root:root" in samba_script


def test_the_samba_script_installs_the_files_with_the_ownership_of_the_spec(
    samba_script: str,
) -> None:
    """The three files go where the spec says, with the modes it says."""
    assert "COLLECTOR_PATH='/usr/local/sbin/newton-ad-samba'" in samba_script
    assert "QUERIES_PATH='/usr/local/lib/newton-ad/queries.json'" in samba_script
    assert "FORBIDDEN_PATH='/usr/local/lib/newton-ad/forbidden.json'" in samba_script
    assert 'install -d -m 0755 -o root -g root "${LIB_DIR}"' in samba_script
    assert (
        'install_blob "${WORK_DIR}/newton-ad-samba" "${COLLECTOR_PATH}" 0755'
        in samba_script
    )
    assert (
        'install_blob "${WORK_DIR}/queries.json" "${QUERIES_PATH}" 0644' in samba_script
    )
    assert (
        'install_blob "${WORK_DIR}/forbidden.json" "${FORBIDDEN_PATH}" 0644'
        in samba_script
    )


def test_the_samba_script_embeds_no_private_key(samba_script: str) -> None:
    """Only the public key of the audit key is in the script."""
    assert f"ssh-ed25519 {KEY_BODY}" in samba_script
    assert "PRIVATE KEY" not in samba_script
    assert "BEGIN OPENSSH" not in samba_script


def test_the_samba_script_holds_no_password(samba_script: str) -> None:
    """No password of any account is in the script.

    The password of the domain account is made by samba-tool and the
    local account has none, so the only password the script names is
    the one that says there is none.
    """
    for number, line in enumerate(samba_script.splitlines(), start=1):
        lowered = line.lower()
        if "password" not in lowered:
            continue
        assert (
            "--random-password" in lowered
            or "--password '!'" in lowered
            or "password_is_locked" in lowered
            or lowered.lstrip().startswith("echo ")
            or lowered.lstrip().startswith("#")
        ), f"line {number}: {line}"


def test_the_samba_blobs_are_the_package_files(samba_script: str) -> None:
    """The three blobs decode to the files the package ships."""
    assert _samba_blob(samba_script, "collector") == setupgen.SAMBA_COLLECTOR_PATH.read_bytes()
    assert _samba_blob(samba_script, "queries") == setupgen.QUERIES_PATH.read_bytes()
    assert _samba_blob(samba_script, "forbidden") == forbidden.dump_json()


def test_the_samba_script_carries_the_hash_of_every_file(samba_script: str) -> None:
    """The script checks every file against the hash of the package."""
    for data in (
        setupgen.SAMBA_COLLECTOR_PATH.read_bytes(),
        setupgen.QUERIES_PATH.read_bytes(),
        forbidden.dump_json(),
    ):
        assert hashlib.sha256(data).hexdigest() in samba_script


def test_the_samba_script_is_idempotent(samba_script: str) -> None:
    """A rerun changes nothing: every file is compared before it is
    written."""
    assert 'cmp -s "${KEYFILE}" "${WORK_DIR}/authorized_keys"' in samba_script
    assert 'if [ -f "$2" ] && [ "$(sha256sum "$2"' in samba_script
    assert 'samba-tool user show "${AUDIT_NAME}" >/dev/null 2>&1' in samba_script
    assert 'getent -s files passwd "${LOGIN_NAME}" >/dev/null 2>&1' in samba_script


def test_the_samba_script_prints_the_inventory_entry(samba_script: str) -> None:
    """The inventory entry names the platform, the host, the user and the
    key."""
    assert 'platform = "ad-samba"' in samba_script
    assert 'host = "${COLLECTOR_HOST}"' in samba_script
    assert 'user = "newton-ssh"' in samba_script
    assert 'user = "${LOGIN_NAME}"' in samba_script
    assert 'domain = "${DOMAIN}"' in samba_script
    assert "key_file = " in samba_script
    assert "known_hosts = " in samba_script


def test_the_samba_script_refuses_a_key_with_an_option() -> None:
    """A key line that carries an option is refused."""
    with pytest.raises(setupgen.SetupError):
        setupgen.samba_script(
            domain="lab.newton.test",
            pubkey='command="x" ssh-ed25519 AAAA',
            device="sambadc",
            host="192.0.2.21",
        )


def test_the_samba_script_refuses_a_host_that_is_not_a_host() -> None:
    """A host outside the grammar is refused."""
    with pytest.raises(setupgen.SetupError):
        setupgen.samba_script(
            domain="lab.newton.test",
            pubkey=setupgen.validate_public_key(PUBLIC_KEY),
            device="sambadc",
            host="a host",
        )


# ---- the Samba script on the fakes ------------------------------------------


def _samba_script_text() -> str:
    """The Samba setup script of the package."""
    return setupgen.samba_script(
        domain="lab.newton.test",
        pubkey=setupgen.validate_public_key(PUBLIC_KEY),
        device="sambadc",
        host="192.0.2.21",
    )


def _run_samba_script(tmp_path: Path, **state):
    """Run the Samba setup script against the fakes of the lab DC."""
    if shutil.which("bash") is None:
        pytest.skip("bash is not on this machine")
    return fake_setup.run_script(_samba_script_text(), tmp_path, **state)


def test_a_first_run_creates_the_login_account_and_leaves_the_domain_one_alone(
    tmp_path: Path,
) -> None:
    """The local account is created and the domain account is left alone.

    The domain account exists already, so the script creates nothing in
    the domain and changes no membership.
    """
    result, calls = _run_samba_script(tmp_path)

    assert result.returncode == 0, result.stderr
    assert any(
        call.startswith("useradd ") and call.endswith(" newton-ssh") for call in calls
    ), calls
    assert not any("samba-tool user create" in call for call in calls), calls


def test_a_rerun_creates_nothing(tmp_path: Path) -> None:
    """A second run finds the local account and creates nothing."""
    script = _samba_script_text()
    first, _ = fake_setup.run_script(script, tmp_path)
    assert first.returncode == 0, first.stderr

    second, calls = fake_setup.run_script(script, tmp_path)

    assert second.returncode == 0, second.stderr
    assert not any(call.startswith("useradd ") for call in calls), calls
    assert not any("samba-tool user create" in call for call in calls), calls


def test_a_primary_group_that_is_not_domain_users_stops_the_script(
    tmp_path: Path,
) -> None:
    """An account whose primary group is not Domain Users stops the
    script before it creates anything."""
    result, calls = _run_samba_script(tmp_path, primary_group="514")

    assert result.returncode != 0
    assert "primary group is not Domain Users" in result.stderr
    assert not any(call.startswith("useradd ") for call in calls), calls


def test_the_script_never_asks_the_identification_of_the_account(
    tmp_path: Path,
) -> None:
    """The local account is never looked up with id -u.

    The domain account resolves locally, so "id" would answer for an
    account that is not there and the script would never create the
    local one.  The script asks for the groups of the account only.
    """
    result, calls = _run_samba_script(tmp_path)

    assert result.returncode == 0, result.stderr
    assert not any(call.startswith("id -u") for call in calls), calls
    assert not any(call.startswith("id -un") for call in calls), calls
    assert any(call.startswith("id -Gn ") for call in calls), calls


def test_the_script_writes_the_sudoers_line_of_the_login_account(
    tmp_path: Path,
) -> None:
    """The sudoers drop-in of the login account is written."""
    result, _ = _run_samba_script(tmp_path)

    assert result.returncode == 0, result.stderr
    sudoers = tmp_path / "etc" / "sudoers.d" / "newton-ssh"
    assert sudoers.is_file()
    text = sudoers.read_text(encoding="utf-8")
    assert text.startswith("newton-ssh ALL=(root) NOPASSWD: ")
    assert text.rstrip().endswith('newton-ad-samba ""')


def test_the_script_installs_the_authorized_key_for_the_login_account(
    tmp_path: Path,
) -> None:
    """The authorized key belongs to root, and it is the key of the account."""
    result, calls = _run_samba_script(tmp_path)

    assert result.returncode == 0, result.stderr
    assert any(
        "install -m 0644 -o root -g root" in call for call in calls
    ), calls
    key = tmp_path / "var" / "lib" / "newton-ssh" / ".ssh" / "authorized_keys"
    assert key.is_file()
    assert 'command="sudo -n ' in key.read_text(encoding="utf-8")


def test_the_script_prints_the_inventory_entry_of_the_login_account(
    tmp_path: Path,
) -> None:
    """The inventory entry names the local account that logs in."""
    result, _ = _run_samba_script(tmp_path)

    assert result.returncode == 0, result.stderr
    assert 'user = "newton-ssh"' in result.stdout
    assert 'platform = "ad-samba"' in result.stdout


# ---- the setup refuses instead of adopting ----------------------------------


def test_an_existing_local_account_with_the_wrong_home_stops_the_script(
    tmp_path: Path,
) -> None:
    """An account whose home is not the one of the key is not adopted."""
    result, calls = _run_samba_script(
        tmp_path, local_account_exists=True, local_home="/home/somebody-else"
    )

    assert result.returncode != 0
    assert "home" in result.stderr
    assert not (tmp_path / "etc" / "sudoers.d" / "newton-ssh").exists()


def test_an_existing_local_account_with_another_shell_stops_the_script(
    tmp_path: Path,
) -> None:
    """An account whose shell is not the one of the script is not adopted."""
    result, calls = _run_samba_script(
        tmp_path, local_account_exists=True, local_shell="/bin/bash"
    )

    assert result.returncode != 0
    assert "shell" in result.stderr
    assert not (tmp_path / "etc" / "sudoers.d" / "newton-ssh").exists()


def test_an_existing_local_account_with_an_unlocked_password_stops_the_script(
    tmp_path: Path,
) -> None:
    """An account whose password is not locked is not adopted."""
    result, calls = _run_samba_script(
        tmp_path, local_account_exists=True, local_locked=False
    )

    assert result.returncode != 0
    assert "password" in result.stderr
    assert not (tmp_path / "etc" / "sudoers.d" / "newton-ssh").exists()


def test_an_existing_local_account_that_is_the_account_of_the_script_is_kept(
    tmp_path: Path,
) -> None:
    """The account of the script is kept and the script goes on."""
    result, calls = _run_samba_script(tmp_path, local_account_exists=True)

    assert result.returncode == 0, result.stderr
    assert not any(call.startswith("useradd ") for call in calls), calls


def test_a_domain_account_that_is_a_member_of_a_group_stops_the_script(
    tmp_path: Path,
) -> None:
    """A domain account that is in a group is not adopted."""
    result, calls = _run_samba_script(
        tmp_path, domain_member_of="CN=Domain Admins,CN=Users,DC=lab,DC=newton,DC=test"
    )

    assert result.returncode != 0
    assert "member of a group" in result.stderr
    assert not any(call.startswith("useradd ") for call in calls), calls


def test_a_primary_group_of_5130_stops_the_script(tmp_path: Path) -> None:
    """A primary group that is not Domain Users stops the script.

    The group must match the whole line, so 5130 is not 513.
    """
    result, calls = _run_samba_script(tmp_path, primary_group="5130")

    assert result.returncode != 0
    assert "primary group is not Domain Users" in result.stderr
    assert not any(call.startswith("useradd ") for call in calls), calls


def test_a_disabled_domain_account_stops_the_script(tmp_path: Path) -> None:
    """A domain account that is disabled stops the script.

    The bit 0x2 of the userAccountControl is the one of a disabled
    account.
    """
    result, calls = _run_samba_script(tmp_path, user_account_control="514")

    assert result.returncode != 0
    assert "disabled" in result.stderr
    assert not any(call.startswith("useradd ") for call in calls), calls


def test_a_sudoers_file_that_differs_is_never_overwritten(tmp_path: Path) -> None:
    """A sudoers file of the host that is not the line of the script stays."""
    sudoers = tmp_path / "etc" / "sudoers.d" / "newton-ssh"
    sudoers.parent.mkdir(parents=True, exist_ok=True)
    original = "newton-ssh ALL=(root) NOPASSWD: /bin/sh\n"
    sudoers.write_text(original, encoding="utf-8")

    result, calls = _run_samba_script(tmp_path)

    assert result.returncode != 0
    assert sudoers.read_text(encoding="utf-8") == original


def test_the_script_stops_when_the_directory_of_the_helper_is_not_root_owned(
    tmp_path: Path,
) -> None:
    """A directory of the helper that root does not own stops the script."""
    state = fake_setup.state_dir_of(tmp_path)
    state.mkdir(parents=True, exist_ok=True)
    fake_setup.set_owner(state, str(tmp_path / "usr" / "local" / "sbin"), 1000, 1000)

    result, calls = _run_samba_script(tmp_path)

    assert result.returncode != 0
    assert "not owned by root" in result.stderr
    assert not (tmp_path / "usr" / "local" / "sbin" / "newton-ad-samba").exists()


def test_the_script_repairs_a_file_of_the_install_with_the_wrong_mode(
    tmp_path: Path,
) -> None:
    """A file that is the file of the package is installed again when its
    mode is wrong."""
    script = _samba_script_text()
    first, _ = fake_setup.run_script(script, tmp_path)
    assert first.returncode == 0, first.stderr

    collector = tmp_path / "usr" / "local" / "sbin" / "newton-ad-samba"
    collector.chmod(0o644)

    second, calls = fake_setup.run_script(script, tmp_path)

    assert second.returncode == 0, second.stderr
    assert any(
        call.startswith("install ") and "newton-ad-samba" in call for call in calls
    ), calls
    assert collector.stat().st_mode & 0o777 == 0o755


def test_the_script_leaves_a_file_of_the_install_that_is_right_alone(
    tmp_path: Path,
) -> None:
    """A file that is the file of the package, with the right mode and
    the right owner, is not installed again."""
    script = _samba_script_text()
    first, _ = fake_setup.run_script(script, tmp_path)
    assert first.returncode == 0, first.stderr

    second, calls = fake_setup.run_script(script, tmp_path)

    assert second.returncode == 0, second.stderr
    assert not any(
        call.startswith("install ") and "newton-ad-samba" in call for call in calls
    ), calls


def test_the_domain_account_exists_after_the_script_created_it(
    tmp_path: Path,
) -> None:
    """The account that the script created is found by the next run."""
    script = _samba_script_text()
    first, _ = fake_setup.run_script(script, tmp_path, domain_user_exists=False)
    assert first.returncode == 0, first.stderr

    second, calls = fake_setup.run_script(script, tmp_path)

    assert second.returncode == 0, second.stderr
    assert not any("samba-tool user create" in call for call in calls), calls


def test_the_spec_and_the_script_name_the_same_authorized_key(
    samba_script: str,
) -> None:
    """The spec of section 7 names the key line of the script."""
    spec = (
        REPO_ROOT / "docs" / "proposals" / "ad" / "SPEC-1.3.md"
    ).read_text(encoding="utf-8")

    assert 'restrict,command="sudo -n /usr/local/sbin/newton-ad-samba"' in spec
    assert 'restrict,command="sudo -n /usr/local/sbin/newton-ad-samba"' in samba_script


# ---- the adoption gap on the local account ----------------------------------


def test_a_planted_file_in_the_ssh_folder_stops_the_script(
    tmp_path: Path,
) -> None:
    """A file that is not the authorized key of the script stops it.

    A planted "authorized_keys2" would be an authorized key of another
    kind, and it would survive the run: the script refuses instead of
    adopting it, and the message names the file.
    """
    home = tmp_path / "var" / "lib" / "newton-ssh" / ".ssh"
    home.mkdir(parents=True)
    (home / "authorized_keys2").write_text("ssh-ed25519 AAAA\n", encoding="utf-8")

    result, calls = _run_samba_script(tmp_path)

    assert result.returncode != 0
    assert "authorized_keys2" in result.stderr
    assert not (tmp_path / "etc" / "sudoers.d" / "newton-ssh").exists()


def test_a_supplementary_group_of_the_account_stops_the_script(
    tmp_path: Path,
) -> None:
    """An account that is in a group besides its primary one stops it.

    The collector runs as root through the forced command of the key,
    and the account needs no group of its own.
    """
    result, calls = _run_samba_script(
        tmp_path, local_account_exists=True, local_groups="newton-ssh wheel"
    )

    assert result.returncode != 0
    assert "group" in result.stderr
    assert not (tmp_path / "etc" / "sudoers.d" / "newton-ssh").exists()


def test_the_home_of_the_account_belongs_to_root(tmp_path: Path) -> None:
    """The home, its .ssh folder and the key belong to root.

    sshd reads the authorized key as root, and StrictModes accepts a
    file of the home of the account that root owns as long as neither
    its group nor the others may write it.
    """
    result, _ = _run_samba_script(tmp_path)

    assert result.returncode == 0, result.stderr
    state = fake_setup.state_dir_of(tmp_path)
    for relative in (
        "var/lib/newton-ssh",
        "var/lib/newton-ssh/.ssh",
        "var/lib/newton-ssh/.ssh/authorized_keys",
    ):
        sidecar = fake_setup.stat_sidecar(state, str(tmp_path / relative))
        assert sidecar.is_file(), relative
        assert "uid=0" in sidecar.read_text(encoding="utf-8"), relative
    assert (tmp_path / "var" / "lib" / "newton-ssh").stat().st_mode & 0o777 == 0o755
    assert (
        tmp_path / "var" / "lib" / "newton-ssh" / ".ssh"
    ).stat().st_mode & 0o777 == 0o755
    key = tmp_path / "var" / "lib" / "newton-ssh" / ".ssh" / "authorized_keys"
    assert key.stat().st_mode & 0o777 == 0o644


# ---- the order of the steps -------------------------------------------------


def test_a_directory_that_is_not_root_owned_leaves_no_sudoers_file(
    tmp_path: Path,
) -> None:
    """A directory of the install that root does not own stops the script.

    The sudoers line is the last thing the script writes, so a run that
    stops before it leaves no sudoers file behind.
    """
    state = fake_setup.state_dir_of(tmp_path)
    state.mkdir(parents=True, exist_ok=True)
    fake_setup.set_owner(state, str(tmp_path / "usr" / "local" / "sbin"), 1000, 1000)

    result, calls = _run_samba_script(tmp_path)

    assert result.returncode != 0
    assert "not owned by root" in result.stderr
    assert not (tmp_path / "usr" / "local" / "sbin" / "newton-ad-samba").exists()
    assert not (tmp_path / "etc" / "sudoers.d" / "newton-ssh").exists()
    assert not any("visudo" in call for call in calls), calls


# ---- the fake visudo --------------------------------------------------------


def _run_visudo(tmp_path: Path, content: str) -> subprocess.CompletedProcess:
    """The fake visudo over a file that holds the given content."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    tool = bin_dir / "visudo"
    tool.write_text(fake_setup.VISUDO, encoding="utf-8")
    tool.chmod(0o755)
    state = fake_setup.state_dir_of(tmp_path)
    state.mkdir(exist_ok=True)
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    environment = dict(os.environ)
    environment["NEWTON_FAKE_LOG"] = str(log)
    environment["NEWTON_FAKE_STATE"] = str(state)
    sudoers = tmp_path / "sudoers"
    sudoers.write_text(content, encoding="utf-8")
    return subprocess.run(
        [str(tool), "-cf", str(sudoers)],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )


def test_the_fake_visudo_refuses_a_line_that_is_not_the_one_of_the_script(
    tmp_path: Path,
) -> None:
    """The fake visudo accepts the one line of the script and no other.

    The real visudo refuses a sudoers file it cannot parse, and the
    script stops when it does.
    """
    accepted = _run_visudo(
        tmp_path,
        'newton-ssh ALL=(root) NOPASSWD: /usr/local/sbin/newton-ad-samba ""\n',
    )
    refused = _run_visudo(
        tmp_path,
        "newton-ssh ALL=(root) NOPASSWD: /bin/sh\n",
    )

    assert accepted.returncode == 0, accepted.stderr
    assert refused.returncode != 0


def test_the_fake_visudo_refuses_a_file_that_holds_more_than_the_one_line(
    tmp_path: Path,
) -> None:
    """The fake visudo accepts a file that holds the line and nothing else.

    A sudoers file that holds the line of the script and another line
    is not the line of the script: the real visudo refuses a file it
    cannot parse, and the script stops when it does.
    """
    refused = _run_visudo(
        tmp_path,
        'newton-ssh ALL=(root) NOPASSWD: /usr/local/sbin/newton-ad-samba ""\n'
        "newton-ssh ALL=(root) NOPASSWD: /bin/sh\n",
    )

    assert refused.returncode != 0


# ---- the owner and the mode of an unchanged file -----------------------------


def _ownership_of(state: Path, path: Path) -> str:
    """The ownership the fake recorded for a path."""
    return fake_setup.stat_sidecar(state, str(path)).read_text(encoding="utf-8")


def test_the_script_repairs_the_owner_and_the_mode_of_an_unchanged_key(
    tmp_path: Path,
) -> None:
    """A key of the right content that the wrong owner holds is repaired.

    The content of the key is the content of the script, so the script
    used to leave the file alone and the owner and the mode of a file
    that sshd reads as root stayed wrong.  The key ends up root:root
    0644.
    """
    script = _samba_script_text()
    first, _ = fake_setup.run_script(script, tmp_path)
    assert first.returncode == 0, first.stderr

    key = tmp_path / "var" / "lib" / "newton-ssh" / ".ssh" / "authorized_keys"
    key.chmod(0o600)
    state = fake_setup.state_dir_of(tmp_path)
    fake_setup.set_owner(
        state,
        str(key),
        1000,
        1000,
        user="newton-ssh",
        group="newton-ssh",
        force=True,
    )

    second, calls = fake_setup.run_script(script, tmp_path)

    assert second.returncode == 0, second.stderr
    assert any(
        call.startswith("install ") and "authorized_keys" in call for call in calls
    ), calls
    assert key.stat().st_mode & 0o777 == 0o644
    ownership = _ownership_of(state, key)
    assert "uid=0" in ownership, ownership
    assert "gid=0" in ownership, ownership
    assert "user=root" in ownership, ownership
    assert "group=root" in ownership, ownership


def test_the_script_repairs_the_mode_of_an_unchanged_key(tmp_path: Path) -> None:
    """A key of the right content and the right owner is repaired when
    its mode is wrong."""
    script = _samba_script_text()
    first, _ = fake_setup.run_script(script, tmp_path)
    assert first.returncode == 0, first.stderr

    key = tmp_path / "var" / "lib" / "newton-ssh" / ".ssh" / "authorized_keys"
    key.chmod(0o600)

    second, calls = fake_setup.run_script(script, tmp_path)

    assert second.returncode == 0, second.stderr
    assert any(
        call.startswith("install ") and "authorized_keys" in call for call in calls
    ), calls
    assert key.stat().st_mode & 0o777 == 0o644


def test_the_script_leaves_an_unchanged_key_that_is_right_alone(
    tmp_path: Path,
) -> None:
    """A key of the right content, the right owner and the right mode is
    not installed again."""
    script = _samba_script_text()
    first, _ = fake_setup.run_script(script, tmp_path)
    assert first.returncode == 0, first.stderr

    second, calls = fake_setup.run_script(script, tmp_path)

    assert second.returncode == 0, second.stderr
    assert not any(
        call.startswith("install ") and "authorized_keys" in call for call in calls
    ), calls


def test_the_script_repairs_the_group_of_an_unchanged_file_of_the_install(
    tmp_path: Path,
) -> None:
    """A file of the install whose group is not root is installed again.

    The owner of the file is root and its mode is right, so the file is
    the file of the package: it is repaired when the group is wrong,
    because the group of a file that root runs is a privilege.
    """
    script = _samba_script_text()
    first, _ = fake_setup.run_script(script, tmp_path)
    assert first.returncode == 0, first.stderr

    collector = tmp_path / "usr" / "local" / "sbin" / "newton-ad-samba"
    state = fake_setup.state_dir_of(tmp_path)
    fake_setup.set_owner(
        state,
        str(collector),
        0,
        1000,
        user="root",
        group="newton-ssh",
        force=True,
    )

    second, calls = fake_setup.run_script(script, tmp_path)

    assert second.returncode == 0, second.stderr
    assert any(
        call.startswith("install ") and "newton-ad-samba" in call for call in calls
    ), calls
    ownership = _ownership_of(state, collector)
    assert "gid=0" in ownership, ownership
    assert "group=root" in ownership, ownership


def test_the_script_repairs_the_owner_and_the_mode_of_an_unchanged_sudoers_file(
    tmp_path: Path,
) -> None:
    """The sudoers file of the right content and the wrong owner is
    repaired.

    The file is read by sudo as root, so its owner and its mode are
    part of the contract of the line.
    """
    script = _samba_script_text()
    first, _ = fake_setup.run_script(script, tmp_path)
    assert first.returncode == 0, first.stderr

    sudoers = tmp_path / "etc" / "sudoers.d" / "newton-ssh"
    sudoers.chmod(0o644)
    state = fake_setup.state_dir_of(tmp_path)
    fake_setup.set_owner(
        state,
        str(sudoers),
        1000,
        1000,
        user="newton-ssh",
        group="newton-ssh",
        force=True,
    )

    second, calls = fake_setup.run_script(script, tmp_path)

    assert second.returncode == 0, second.stderr
    assert sudoers.stat().st_mode & 0o777 == 0o440
    ownership = _ownership_of(state, sudoers)
    assert "uid=0" in ownership, ownership
    assert "user=root" in ownership, ownership
