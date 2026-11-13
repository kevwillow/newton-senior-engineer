"""Step 0 proves the policy backup itself.

The setup of the earlier build ran on the real PDC
``WSBXDC1.win2.newton.test`` OVER AN SSH KEY LOGIN (an S4U logon,
``klist``: ``Cache Flags: 0x4 -> S4U``).  The step 0 printed "This
session can read the share of the PDC.", the steps 1 to 5 completed,
and the step 6 stopped:

```
Backup-GPO : Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
```

Right after, in the same kind of key session, this was measured:

- the GPT.INI read of the PDC share: OK;
- opening GptTmpl.inf for write: OK;
- ``Backup-GPO -Server <PDC>``: FAIL, E_ACCESSDENIED;
- ``Backup-GPO`` without ``-Server``: FAIL;
- ``\\\\win2.newton.test\\SYSVOL``: Access is denied.

The same step 6 code passed over a key login earlier the same day (the
sixth run of ``MEASURED-2026-11-09.md``).  So over an S4U session
``Backup-GPO`` is unreliable, and the read of the GPT.INI of the step 0
does not predict it: the earlier rule ("an S4U session reaches the
share of the controller it runs on") is true for the reads of the files
and false as a promise about ``Backup-GPO``.

The step 0 therefore takes the backup of the policy itself, before the
step 1, and a run that cannot back the policy up stops there, before
anything in the domain is changed.

Every test that runs the script runs it against a fake of Active
Directory whose answers are the measured ones.  The helpers of these
tests are in ``windows_run.py``.
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
    DEVICE,
    HOST,
    OPS_SID,
    OU,
    PDC,
    PDC_POLICY_PATH,
    PUBLIC_KEY,
    ROLE_OWNER,
    fake_model,
    powershell_prelude,
    recorded_calls,
    reset_password_right,
    run_program,
    step_text,
    step_zero_without_the_elevation_check,
)

from newton_mcp.ad import setupgen_write as write


REPO_ROOT = Path(__file__).resolve().parents[3]

#: The measured facts.
MEASURED = REPO_ROOT / "docs" / "proposals" / "ad" / "MEASURED-2026-11-09.md"

#: The path of the GPT.INI of the policy of the PDC, the way the script
#: builds it: the share of the SYSVOL of the PDC, and not the share of
#: the name of the domain.
GPT_INI_PATH = (
    f"\\\\{PDC}\\SYSVOL\\{DOMAIN}\\Policies\\{{{DEFAULT_DC_POLICY_GUID}}}"
    "\\GPT.INI"
)

#: The refusal of a session that cannot back the policy up, with the path of the policy of
#: the PDC in it: the owner has to see what the check measured.
REFUSAL = (
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

#: The statements that are gone.  They said that a key login reaches the
#: share of its own controller and that it can back the policy up: the
#: measurement says that the backup is unreliable over such a session.
GONE = (
    "the share of the controller it runs on",
    "cannot be backed up or edited",
    "Run this script from the console",
)


def refusal(path: str = GPT_INI_PATH) -> str:
    """The refusal, with the path of the policy of the PDC."""
    return REFUSAL.replace("{path}", path)


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


def step_program(script: str, tmp_path: Path, *steps: int) -> str:
    """The program that runs the step 0 and the steps of the run.

    The step 0 runs without the check of the elevation: that check is a
    Windows behaviour, and the machine of the tests has no
    ``WindowsIdentity``.

    The state of the fake is written when the step 0 is over, and
    again at the end of the run: a run that stops in the step 0 exits
    there, and the state of the fake is what says that nothing was
    changed.
    """
    state = (
        "@{ calls = @($script:FakeCalls); dsacls = @($script:FakeDsacls);"
        " writes = @($script:FakeWrites); reads = @($script:FakeReads) } |"
        " ConvertTo-Json -Depth 8 |"
        " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8"
    )
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            "function Resolve-NewtonAccountSid { param([string]$Name) return '"
            + OPS_SID
            + "' }",
            BACKUP_ROOT_LINE,
            f"$env:TEMP = '{tmp_path}'",
            "try {",
            step_zero_without_the_elevation_check(script),
            "} finally {",
            state,
            "}",
            *[step_text(script, number) for number in steps],
            state,
        ]
    )


# ---- the step 0 takes the backup --------------------------------------------


def test_the_step_0_backs_the_policy_up(windows_script: str, tmp_path: Path) -> None:
    """The step 0 backs the policy up, before the step 1.

    The backup is the check that matters: over an S4U session the read
    of the GPT.INI may answer and the backup may fail.
    """
    result, recorded = run_program(
        step_program(windows_script, tmp_path, 1), tmp_path, policy_model(tmp_path)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    backups = recorded_calls(recorded, "Backup-GPO")
    assert len(backups) == 1, recorded["calls"]
    assert backups[0]["guid"] == DEFAULT_DC_POLICY_GUID
    assert backups[0]["server"] == PDC
    assert backups[0]["path"].startswith(str(tmp_path / "gpo-backup"))


def test_the_backup_of_the_step_0_is_in_a_timestamped_folder(
    windows_script: str, tmp_path: Path
) -> None:
    """The backup goes into a folder of its own, named after the time.

    The folder carries the stamp of the run, so a second run does not
    write over the backup of the first one.
    """
    result, recorded = run_program(
        step_program(windows_script, tmp_path, 1), tmp_path, policy_model(tmp_path)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    backups = recorded_calls(recorded, "Backup-GPO")
    stamp = Path(str(backups[0]["path"])).name
    assert len(stamp) == 15, stamp
    assert stamp[8] == "-", stamp
    assert stamp.replace("-", "").isdigit(), stamp


def test_the_backup_is_taken_before_the_step_1(windows_script: str) -> None:
    """The backup of the step 0 comes before the step 1.

    A run that cannot back the policy up stops before the account of
    the write account is created and before the delegation is granted.
    """
    prechecks = step_text(windows_script, 0)

    assert (
        "Backup-GPO -Guid $DefaultDcPolicyGuid -Path $backupDir -Server $PdcServer"
        in prechecks
    )
    assert prechecks.index("Backup-GPO") < windows_script.index("Step 1:")


def test_the_step_0_keeps_the_read_of_the_gpt_ini(
    windows_script: str, tmp_path: Path
) -> None:
    """The read of the GPT.INI of the policy stays in the step 0.

    It is the check of the share of the PDC, and the run reads the
    file of the policy of the PDC there and nowhere else.
    """
    result, recorded = run_program(
        step_program(windows_script, tmp_path, 1), tmp_path, policy_model(tmp_path)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert GPT_INI_PATH in recorded["reads"], recorded["reads"]


def test_step_0_reads_the_guid_of_the_domain_head(
    windows_script: str, tmp_path: Path
) -> None:
    """The step 0 reads the objectGUID of the head of the domain.

    The entry of the controller carries that guid, and the maq verb
    targets the head of the domain by it alone: the value the step 0
    computes is the value the entry holds, so the step 0 is run here
    and its value is read.
    """
    program = step_program(windows_script, tmp_path) + (
        "\nWrite-Host ('GUID=' + $DomainHeadGuid)"
    )

    result, _ = run_program(program, tmp_path, policy_model(tmp_path))

    assert result.returncode == 0, result.stdout + result.stderr
    assert "GUID=" + DOMAIN_HEAD_GUID in result.stdout


# ---- the backup that fails stops the run ------------------------------------


def test_a_backup_that_fails_stops_the_run_before_any_change(
    windows_script: str, tmp_path: Path
) -> None:
    """The run stops in the step 0 when the backup of the policy fails.

    The fake makes ``Backup-GPO`` throw E_ACCESSDENIED while the read
    of the GPT.INI answers, the way it was measured.  Nothing
    is changed: the account of the write account is not created, the
    delegation is not granted, and the policy is not written.
    """
    model = policy_model(tmp_path, backupGpoAccessDenied=True, users=[])

    result, recorded = run_program(
        step_program(windows_script, tmp_path, 1, 2), tmp_path, model
    )

    assert result.returncode != 0
    assert refusal() in result.stdout, result.stdout
    assert "Step 1: the newton-ops account" not in result.stdout
    assert "Step 2: the delegation" not in result.stdout
    assert recorded_calls(recorded, "New-ADUser") == []
    assert recorded_calls(recorded, "Set-ADObject") == []
    assert recorded["dsacls"] == []
    assert recorded["writes"] == []


def test_the_refusal_is_printed_once(windows_script: str, tmp_path: Path) -> None:
    """The refusal is one line, and the owner reads one line.

    The line names the policy of the PDC and the way to run the
    script.
    """
    model = policy_model(tmp_path, backupGpoAccessDenied=True, users=[])

    result, _ = run_program(
        step_program(windows_script, tmp_path, 1, 2), tmp_path, model
    )

    assert result.returncode != 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines.count(refusal()) == 1, result.stdout


def test_the_read_of_the_share_does_not_promise_the_backup(
    windows_script: str, tmp_path: Path
) -> None:
    """A session that reads the share and cannot back the policy up is
    refused.

    The earlier step 0 read the GPT.INI of the policy and called the
    run good; it was measured that the backup fails in such a
    session, and the run before this fix stopped at the step 6 with the
    domain half changed.
    """
    model = policy_model(tmp_path, backupGpoAccessDenied=True, users=[])

    result, recorded = run_program(
        step_program(windows_script, tmp_path, 1), tmp_path, model
    )

    assert result.returncode != 0
    assert "This session can read the share of the PDC." in result.stdout
    assert refusal() in result.stdout, result.stdout


# ---- the step 6 uses that backup ---------------------------------------------


def test_the_step_6_takes_no_second_backup(windows_script: str) -> None:
    """The step 6 does not take a backup of its own.

    The backup is made once, in the step 0, and the step 6 prints the
    line of it.
    """
    assert "Backup-GPO" not in step_text(windows_script, 6)


def test_the_run_takes_one_backup_and_the_step_6_prints_it(
    windows_script: str, tmp_path: Path
) -> None:
    """The run takes one backup, and the step 6 prints that one.

    The backup is taken before the read of the policy of the step 6:
    the order of the recorded calls is the order of the run.
    """
    result, recorded = run_program(
        step_program(windows_script, tmp_path, 1, 6), tmp_path, policy_model(tmp_path)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    calls = recorded["calls"]
    backups = recorded_calls(recorded, "Backup-GPO")
    reads = recorded_calls(recorded, "Get-GPO")
    assert len(backups) == 1, calls
    assert len(reads) == 1, calls
    names = [str(call.get("cmdlet")) for call in calls]
    assert names.index("Backup-GPO") < names.index("Get-GPO"), names
    assert (
        "The Default Domain Controllers Policy is backed up in "
        + str(backups[0]["path"])
    ) in result.stdout


# ---- the words --------------------------------------------------------------


def test_the_refusal_of_the_module_is_the_line_the_setup_prints() -> None:
    """The refusal of the module is the refusal line the setup prints.

    The name of the constant follows what it now means: the refusal is
    not the refusal of a session that cannot read the share, it is the
    refusal of a session that cannot back the policy up.
    """
    from newton_mcp.ad import setupgen_write as write

    assert REFUSAL.startswith(REFUSAL_HEAD + "{path})")
    assert not hasattr(write, "NO_PDC_SHARE")
    assert hasattr(write, "NO_POLICY_BACKUP")
    assert "{path}" in write.NO_POLICY_BACKUP
    assert write.NO_POLICY_BACKUP.replace("{path}", GPT_INI_PATH) == refusal()


def test_the_header_says_what_was_measured(windows_script: str) -> None:
    """The header says the measured facts and not the old rule.

    The old rule of the share check was too strong: an S4U session may read the
    share of the controller it runs on, and the backup of the policy is
    unreliable over such a session.
    """
    header = comments(windows_script[: windows_script.index("Step 0:")])

    assert "S4U" in header
    assert "Backup-GPO" in header
    assert "E_ACCESSDENIED" in header
    assert "unreliable" in header
    for phrase in GONE:
        assert phrase not in header, phrase


def test_the_comment_of_the_step_0_says_what_was_measured(
    windows_script: str,
) -> None:
    """The comment of the step 0 says what the check measures.

    The step 0 backs the policy up, and it stops the run before any
    change when it cannot.
    """
    said = comments(step_text(windows_script, 0))

    assert "S4U" in said
    assert "Backup-GPO" in said
    assert "E_ACCESSDENIED" in said
    assert "does not promise" in said
    for phrase in GONE:
        assert phrase not in said, phrase


def test_the_script_says_nothing_about_a_key_login_that_works(
    windows_script: str,
) -> None:
    """The whole script carries no statement of the old rule.

    Not the header, and not a comment of a step: the script backs the
    policy up itself, and it says what happens when it cannot.
    """
    said = comments(windows_script)

    for phrase in GONE:
        assert phrase not in said, phrase
    assert "cannot be backed up or edited" not in said


# ---- the measured document --------------------------------------------------


def test_the_measured_document_carries_the_seventh_run() -> None:
    """The measured document holds the run of this fix.

    It keeps the earlier measurements, and it says that the old rule of
    the share check was too strong.
    """
    text = MEASURED.read_text(encoding="utf-8")
    start = text.index("## Windows setup, measured 2026-11-09, seventh run")
    section = text[start:]

    assert "E_ACCESSDENIED" in section
    assert "Backup-GPO" in section
    assert "too strong" in section
    # The two earlier runs are kept.
    assert "## Windows setup, measured 2026-11-09, third run" in text
    assert "## Windows setup, measured 2026-11-09, sixth run" in text


# ---- the warning of a controller that names itself ---------------------------


#: The role owner of the domain when this controller does not hold the
#: PDC emulator role: another controller of the domain holds it.
OTHER_ROLE_OWNER = ROLE_OWNER.replace("CN=WINDC1", "CN=WINDC2")

#: The head of the warning the setup prints.
WARNING_HEAD = "WARNING: this DC does not hold the PDC emulator role"


def non_pdc_model(tmp_path: Path) -> dict[str, Any]:
    """The model of a controller that does not hold the PDC role.

    The rootDSE of a controller names its own NTDS Settings object and
    the head of the domain names the object of the controller that
    holds the role: the two differ on a controller that is not the PDC.
    """
    model = policy_model(tmp_path)
    model["objects"][0]["fSMORoleOwner"] = OTHER_ROLE_OWNER
    return model


def test_a_non_pdc_that_names_itself_is_warned(
    windows_script: str, tmp_path: Path
) -> None:
    """A controller that does not hold the role and names itself is warned.

    The entry of a controller that names itself is a second device
    standing for the domain: the loader of the inventory refuses it
    when another DC of the domain has an entry too.  The setup warns
    the owner before that happens.
    """
    result, _ = run_program(
        step_program(windows_script, tmp_path), tmp_path, non_pdc_model(tmp_path)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "does not hold the PDC emulator role" in result.stdout
    assert WARNING_HEAD in result.stdout


def test_a_non_pdc_that_names_another_device_is_not_warned(
    windows_script: str, tmp_path: Path
) -> None:
    """A controller that names the device of the domain is not warned.

    The entry of a controller that does not hold the role names the
    device that stands for the domain: that is the way it is set up,
    and there is nothing to warn about.
    """
    script = write.windows_write_script(
        domain=DOMAIN,
        pubkey=write.validate_public_key(PUBLIC_KEY),
        device=DEVICE,
        host=HOST,
        ous=[OU],
        domain_device="windc-pdc",
    )

    result, _ = run_program(
        step_program(script, tmp_path), tmp_path, non_pdc_model(tmp_path)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert WARNING_HEAD not in result.stdout


def test_a_pdc_that_names_itself_is_not_warned(
    windows_script: str, tmp_path: Path
) -> None:
    """The controller that holds the role names itself and is not warned.

    The entry of the PDC emulator stands for the domain: it is the one
    device of the domain, and there is nothing to warn about.
    """
    result, _ = run_program(
        step_program(windows_script, tmp_path), tmp_path, policy_model(tmp_path)
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "holds the PDC emulator role" in result.stdout
    assert WARNING_HEAD not in result.stdout
