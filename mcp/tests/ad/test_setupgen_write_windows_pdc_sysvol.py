"""The network credentials and the SYSVOL of the PDC.

The Windows script printed by the earlier build ran (with the
Windows write helper merged in, so ``write.ps1`` was there) on the real
Server 2025 PDC ``WSBXDC1.win2.newton.test`` under Windows PowerShell
5.1, and the account ``newton-ops`` had been deleted first.

- **Over an SSH key login**, the steps 0 to 5 worked: 25 ACEs were
  added and the fingerprint of the approval key matched.  The step 6
  stopped at ``Backup-GPO : Access is denied. (Exception from HRESULT:
  0x80070005 (E_ACCESSDENIED))``.
- **Over an SSH password login**, the same script ran to the end: the
  steps 0 to 5 were there, the step 6 backed the policy up, granted the
  right, bumped the version to 6 and verified it with secedit, and the
  steps 7 and 8 worked.
- **On WSBXDC2**, the controller that is not the PDC, the script worked
  over an SSH key login, because the step 6 does nothing there.

Measured in the key login session: ``klist`` shows ``Cache Flags: 0x4
-> S4U``, the session has no network credentials, and the share
``\\\\win2.newton.test\\SYSVOL`` answers ``Access is denied``.  Measured
in the password login session: the session holds a real ticket of the
domain, and the share of the domain name was served by the OTHER
controller, ``cifs/WSBXDC2.win2.newton.test``, even though the session
ran on the PDC.

A later reading of that measurement corrected it: the share of the
name of the domain was served by the OTHER controller, and an S4U
session reaches the share of the controller it runs on and no other.
The pre-check stays, and it is the pre-check of the share of the PDC.

A later run corrected it once more: it measured that the backup
of the policy is unreliable over an S4U session (the same code had
passed over a key login earlier the same day, and it failed over
another one), and that the read of the GPT.INI of the policy does not
predict the backup.  The step 0 therefore takes the backup of the
policy itself, before the step 1, and it prints the refusal of a
session that cannot back the policy up.

The three items below are the ones that run found, and every test that
runs the script runs it against a fake of Active Directory whose
answers are the measured ones.  The helpers of these tests are in
``windows_run.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from windows_run import (
    AD_FAKE,
    BACKUP_ROOT_LINE,
    DEFAULT_DC_POLICY_GUID,
    DOMAIN,
    DOMAIN_DN,
    DOMAIN_HEAD_GUID,
    OPS_SID,
    OU,
    PDC,
    PDC_POLICY_PATH,
    ROLE_OWNER,
    fake_model,
    powershell_prelude,
    recorded_calls,
    reset_password_right,
    run_program,
    step_text,
)


#: The refusal of a session that cannot back the policy of the PDC up.
#: It is one line, and the path of the policy
#: is in it: the owner has to see what the check measured.  The path is
#: filled in by the script when it runs.
NO_BACKUP = (
    "This session cannot back up the Default Domain Controllers Policy "
    "on the PDC ({path}), so the policy cannot be edited. Run this script "
    "on the PDC in a session with network credentials: an interactive "
    "logon, or a remote logon made with a password. An SSH key login "
    "(an S4U logon) cannot do this reliably."
)

#: The head of the refusal: the part of it that is typed in the script.
REFUSAL_HEAD = (
    "This session cannot back up the Default Domain Controllers Policy on the PDC ("
)

#: The path of the GPT.INI of the policy of the PDC, the way the script
#: builds it: the share of the SYSVOL of the PDC.
GPT_INI_PATH = (
    f"\\\\{PDC}\\SYSVOL\\{DOMAIN}\\Policies\\{{{DEFAULT_DC_POLICY_GUID}}}"
    "\\GPT.INI"
)


def refusal(path: str = GPT_INI_PATH) -> str:
    """The refusal, with the path of the policy of the PDC."""
    return NO_BACKUP.replace("{path}", path)


def comments(script: str) -> str:
    """The comments of the script, unfolded into one text.

    The comments of the script are wrapped, and a phrase of them may
    run over two lines: the text is joined before it is read.
    """
    lines = [
        line.strip()
        for line in script.splitlines()
        if line.strip().startswith("#")
    ]
    return " ".join(line.lstrip("#").strip() for line in lines)


def step_zero_without_the_elevation_check(script: str) -> str:
    """The step 0 without the check of the elevation.

    The check is a Windows behaviour: ``WindowsIdentity`` does not exist
    on the machine of the tests, so the fake of the session answers that
    the session is elevated.  Every other check of the step 0 runs as
    the script has it.
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


def policy_model(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    """The model of the domain, with the policy of the PDC in a sandbox.

    The folder of the sandbox stands for the share of the SYSVOL of the
    PDC: the fake serves the path of the share from it.
    """
    policy = tmp_path / "policy"
    machine = policy / "Machine" / "Microsoft" / "Windows NT" / "SecEdit"
    machine.mkdir(parents=True)
    (policy / "GPT.INI").write_text("[General]\r\nVersion=7\r\n", encoding="ascii")
    (machine / "GptTmpl.inf").write_bytes(
        "[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\n"
        "SeBatchLogonRight = *S-1-5-32-551\r\n".encode("utf-16-le") + b"\xff\xfe"
    )
    model = fake_model(
        objects=[
            {
                "DistinguishedName": DOMAIN_DN,
                "objectClass": ["domainDNS"],
                "fSMORoleOwner": ROLE_OWNER,
                # The head of the domain carries its objectGUID: the
                # setup reads it to print the ad_domain_guid of the
                # entry.
                "objectGuid": DOMAIN_HEAD_GUID,
            },
            {"DistinguishedName": OU, "objectClass": ["organizationalUnit"]},
            reset_password_right(),
            {
                "DistinguishedName": (
                    f"CN={{{DEFAULT_DC_POLICY_GUID}}},CN=Policies,CN=System,"
                    f"{DOMAIN_DN}"
                ),
                "objectClass": ["groupPolicyContainer"],
                "versionNumber": 3,
                "gPCFileSysPath": PDC_POLICY_PATH,
            },
        ],
        policyDir=str(policy),
        userRights=(
            "[Unicode]\nUnicode=yes\n[Privilege Rights]\n"
            "SeBatchLogonRight = newton-ops,*S-1-5-32-544\n"
        ),
    )
    model.update(overrides)
    return model


# ---- the pre-check for network credentials -----------------------------------


def test_the_pre_check_is_on_the_pdc_only(windows_script: str) -> None:
    """The check of the share of the PDC runs on the PDC only.

    The controller that is not the PDC does not touch the policy at
    all, so it needs no share: the key login works there.
    """
    prechecks = step_text(windows_script, 0)
    assert "if ($isPdc) {" in prechecks
    assert prechecks.index("if ($isPdc) {") < prechecks.index(REFUSAL_HEAD)


def test_the_refusal_is_one_line(windows_script: str, tmp_path: Path) -> None:
    """The refusal of a session that cannot read the share is one line.

    The line is the one refusal line, it names the path of the file
    that could not be read, and it is printed before any change: the
    run stops in the step 0.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            BACKUP_ROOT_LINE,
            step_zero_without_the_elevation_check(windows_script),
            step_text(windows_script, 1),
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(
        program, tmp_path, policy_model(tmp_path, sysvolAccessDenied=True)
    )

    assert result.returncode != 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines.count(refusal()) == 1, result.stdout
    assert "Step 1: the newton-ops account" not in result.stdout


def test_a_session_without_network_credentials_stops_in_step_0(
    windows_script: str, tmp_path: Path
) -> None:
    """The run stops in the step 0 when the share cannot be read.

    The fake makes the read of the share throw, the way the measured key login
    made ``Backup-GPO`` fail with E_ACCESSDENIED.  The
    step 0 refuses, the step 1 never runs, and the refusal line is
    printed.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            BACKUP_ROOT_LINE,
            step_zero_without_the_elevation_check(windows_script),
            step_text(windows_script, 1),
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(
        program, tmp_path, policy_model(tmp_path, sysvolAccessDenied=True)
    )

    assert result.returncode != 0
    assert refusal() in result.stdout
    assert "Step 1: the newton-ops account" not in result.stdout


def test_the_pre_check_reads_the_gpt_ini_of_the_pdc(
    windows_script: str, tmp_path: Path
) -> None:
    """The pre-check reads the GPT.INI of the policy through the share of
    the PDC.

    The path is the share of the PDC, ``\\\\<PDC>\\SYSVOL\\<domain>\\Policies\\{<guid>}``,
    and not the name of the domain: the name of the domain may be served
    by another controller, and the policy of the PDC is not there.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            BACKUP_ROOT_LINE,
            step_zero_without_the_elevation_check(windows_script),
            "@{ reads = @($script:FakeReads) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(program, tmp_path, policy_model(tmp_path))

    assert result.returncode == 0, result.stdout + result.stderr
    wanted = (
        f"\\\\{PDC}\\SYSVOL\\{DOMAIN}\\Policies\\{{{DEFAULT_DC_POLICY_GUID}}}"
        "\\GPT.INI"
    )
    assert wanted in recorded["reads"], recorded["reads"]


def test_the_pre_check_does_not_stop_a_controller_that_is_not_the_pdc(
    windows_script: str, tmp_path: Path
) -> None:
    """A controller that is not the PDC is not stopped by the check.

    The measured run on ``WSBXDC2`` worked over an SSH
    key login: the step 6 does nothing there, so the step 6 needs no
    network credentials.
    """
    other = (
        "CN=NTDS Settings,CN=WINDC2,CN=Servers,CN=Default-First-Site-Name,"
        f"CN=Sites,CN=Configuration,{DOMAIN_DN}"
    )
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            BACKUP_ROOT_LINE,
            step_zero_without_the_elevation_check(windows_script),
            step_text(windows_script, 1),
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(program, tmp_path, fake_model(roleOwner=other))

    assert result.returncode == 0, result.stdout + result.stderr
    assert refusal() not in result.stdout
    assert "Step 1: the newton-ops account" in result.stdout
    assert recorded_calls(recorded, "Get-ADUser")


# ---- the SYSVOL of the PDC --------------------------------------------------


def test_the_script_never_uses_the_name_of_the_domain_for_the_sysvol(
    windows_script: str,
) -> None:
    """The share of the SYSVOL is the share of the PDC, and never the
    share of the name of the domain.

    The name of the domain may be served by another controller: the
    policy of the PDC is not there, and the edit would land in the
    wrong place.
    """
    for share in ("SYSVOL", "SysVol", "sysvol"):
        assert f"\\\\{DOMAIN}\\{share}" not in windows_script
        assert f"\\\\{DOMAIN.upper()}\\{share}" not in windows_script


def test_the_pdc_is_named_by_its_pdc_emulator(windows_script: str) -> None:
    """The PDC is named by ``(Get-ADDomain).PDCEmulator``.

    The measured answer of the cmdlet is the FQDN of the controller.
    """
    assert "(Get-ADDomain).PDCEmulator" in windows_script


def test_the_backup_and_the_read_of_the_policy_carry_the_pdc(
    windows_script: str, tmp_path: Path
) -> None:
    """``Backup-GPO`` and ``Get-GPO`` are called with the PDC.

    Both cmdlets talk to a server, and the server is the PDC: the
    policy of the PDC is not on the other controller.  The backup is
    taken by the step 0 and the read of the policy by the step 6, and
    there is one of each in the run.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Resolve-NewtonAccountSid { param([string]$Name) return '"
            + OPS_SID
            + "' }",
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            BACKUP_ROOT_LINE,
            "$isPdc = $true",
            f"$opsSid = '{OPS_SID}'",
            f"$env:TEMP = '{tmp_path}'",
            step_zero_without_the_elevation_check(windows_script),
            step_text(windows_script, 6),
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(program, tmp_path, policy_model(tmp_path))

    assert result.returncode == 0, result.stdout + result.stderr
    backups = recorded_calls(recorded, "Backup-GPO")
    assert len(backups) == 1
    assert backups[0]["server"] == PDC
    reads = recorded_calls(recorded, "Get-GPO")
    assert len(reads) == 1
    assert reads[0]["server"] == PDC


def test_the_files_of_the_policy_are_edited_in_the_share_of_the_pdc(
    windows_script: str, tmp_path: Path
) -> None:
    """The template and the version of the policy are edited in the
    share of the PDC.

    The path of the policy the directory answers is not the path that
    is written: the write lands in
    ``\\\\<PDC>\\SYSVOL\\<domain>\\Policies\\{<guid>}``.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(windows_script),
            "function Resolve-NewtonAccountSid { param([string]$Name) return '"
            + OPS_SID
            + "' }",
            "$isPdc = $true",
            f"$opsSid = '{OPS_SID}'",
            f"$GpoBackupRoot = '{tmp_path / 'gpo-backup'}'",
            # The backup of the policy is made by the step 0, and this
            # program runs the step 6 alone.
            "$backupDir = Join-Path $GpoBackupRoot '20261109-000000'",
            f"$env:TEMP = '{tmp_path}'",
            step_text(windows_script, 6),
            "@{ calls = @($script:FakeCalls); writes = @($script:FakeWrites) } |"
            " ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )

    result, recorded = run_program(program, tmp_path, policy_model(tmp_path))

    assert result.returncode == 0, result.stdout + result.stderr
    folder = f"\\\\{PDC}\\SYSVOL\\{DOMAIN}\\Policies\\{{{DEFAULT_DC_POLICY_GUID}}}"
    template = folder + "\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
    ini = folder + "\\GPT.INI"
    assert template in recorded["writes"], recorded["writes"]
    assert ini in recorded["writes"], recorded["writes"]
    # The folder of the sandbox holds the edit: the right is there, and
    # the version of the policy went up.
    policy = tmp_path / "policy"
    text = (policy / "Machine" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf").read_bytes()
    assert text.decode("utf-16-le").count("SeBatchLogonRight") == 1
    assert OPS_SID in text.decode("utf-16-le")
    assert "Version=8" in (policy / "GPT.INI").read_text(encoding="ascii")


def test_the_path_of_the_policy_is_not_the_path_that_is_written(
    windows_script: str,
) -> None:
    """The path the directory answers is only read, and never written.

    The script may read ``gPCFileSysPath`` to prove that the policy is
    the one of its own GUID, but the path it writes is the one of the
    share of the PDC.
    """
    assert "Join-Path $gpoDir" not in windows_script
    assert "$gpoDir 'Machine" not in windows_script
    assert "gPCFileSysPath" in windows_script


# ---- the header of the script -----------------------------------------------


def test_the_header_says_how_the_policy_is_reached(
    windows_script: str,
) -> None:
    """The header of the script says how the policy is reached.

    The policy of the PDC is edited through the share of the SYSVOL of
    the PDC, and the share of the name of the domain may be served by
    another controller.  An SSH key login is an S4U logon, and the
    backup of the policy is unreliable over such a session.
    """
    header = comments(windows_script[: windows_script.index("Step 0:")])
    assert "edited in the share of the SYSVOL of the PDC" in header
    assert "the share of the name of the domain may be served by another controller" in header
    assert "S4U" in header
    assert "E_ACCESSDENIED" in header
    assert "unreliable" in header
