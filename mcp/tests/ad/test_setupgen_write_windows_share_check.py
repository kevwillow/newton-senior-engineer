"""The share check says what was measured.

The script of the earlier build (with the PDC share pre-check, the
reset-password grant and its lookup by name, and the write helper that
voids its collection indexes) ran on the real PDC
``WSBXDC1.win2.newton.test`` OVER AN SSH KEY LOGIN (an S4U logon,
``klist``: ``Cache Flags: 0x4 -> S4U``).  It ran to the end:

- the step 0 printed "This session can read the share of the PDC.";
- 27 ACEs were present;
- the step 6 backed the policy up, granted the right (version 8) and
  verified it with secedit.

Measured in that key session:

- ``\\\\WSBXDC1.win2.newton.test\\SYSVOL\\...\\GPT.INI``: read OK;
- ``Backup-GPO -Server <PDC>``: OK;
- the GptTmpl.inf of the PDC share, opened for write: OK;
- ``\\\\WSBXDC2.win2.newton.test\\SYSVOL\\...\\GPT.INI``: FAIL,
  "Cannot find path ... because it does not exist".

So the true rule is: an S4U session reaches the SYSVOL share of the
controller it runs on, and not the share of another controller.  The
pre-check of the share of the PDC stays a fail-closed guard, but its words and the
header comment were wrong: they said that an SSH key login cannot
back the policy up and cannot edit it.

A later run corrected that rule once more: it measured that the
backup of the policy is unreliable over an S4U session (the same code
had passed over a key login earlier the same day, and it failed over
another one), and that the read of the GPT.INI of the policy does not
predict the backup.  The step 0 therefore takes the backup of the
policy itself, and it prints the refusal of a session that cannot back
the policy up.

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
    PDC,
    fake_model,
    powershell_prelude,
    run_program,
    step_text,
    step_zero_without_the_elevation_check,
)


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

#: The refusal the setup prints, with the path of the policy of the PDC.
#: The path is the one the script reads: the owner has to see what the
#: check measured.
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

#: The tail of the refusal: the part of it that follows the path.
REFUSAL_TAIL = (
    "), so the policy cannot be edited. Run this script on the PDC in a "
    "session with network credentials: an interactive logon, or a remote "
    "logon made with a password. An SSH key login (an S4U logon) cannot "
    "do this reliably."
)

#: The statements that are gone.  They said that a key login reaches
#: the share of its own controller and that it can back the policy up:
#: the later measurement says that the backup of the policy is
#: unreliable over such a session.
GONE = (
    "cannot be backed up or edited",
    "the share of the controller it runs on",
    "Run this script from the console",
)


def refusal(path: str = GPT_INI_PATH) -> str:
    """The refusal, with the path of the file that was read."""
    return REFUSAL.replace("{path}", path)


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
    model = fake_model(policyDir=str(policy))
    model.update(overrides)
    return model


def step_zero_program(script: str) -> str:
    """The program that runs the step 0 of the script against the fake."""
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            BACKUP_ROOT_LINE,
            step_zero_without_the_elevation_check(script),
            step_text(script, 1),
            "@{ calls = @($script:FakeCalls); reads = @($script:FakeReads) } |"
            " ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )


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


# ---- the refusal line ---------------------------------------------------------


def test_the_refusal_is_the_line_the_setup_prints(
    windows_script: str, tmp_path: Path
) -> None:
    """The refusal is the one line the setup prints, with the real path.

    The path in it is the path of the GPT.INI of the policy of the
    PDC: the file the check reads.
    """
    result, _ = run_program(
        step_zero_program(windows_script),
        tmp_path,
        policy_model(tmp_path, sysvolAccessDenied=True),
    )

    assert result.returncode != 0
    assert refusal() in result.stdout, result.stdout
    assert "Step 1: the newton-ops account" not in result.stdout


def test_the_refusal_carries_the_path_the_script_reads(
    windows_script: str,
) -> None:
    """The path of the refusal is the path the script reads.

    It is the variable of the GPT.INI of the policy, and not a path
    typed in the script: the path of the share of the PDC is built from
    the PDC emulator, the domain and the GUID of the policy.
    """
    prechecks = step_text(windows_script, 0)
    assert "$GptIniPath" in prechecks

    header = windows_script[: windows_script.index("Step 0:")]
    assert (
        "$PdcPolicyDir = '\\\\' + $PdcServer + '\\SYSVOL\\' + $Domain +"
        " '\\Policies\\{' + $DefaultDcPolicyGuid + '}'" in header
    )
    assert "$GptIniPath = $PdcPolicyDir + '\\GPT.INI'" in header


def test_the_refusal_is_one_line(windows_script: str, tmp_path: Path) -> None:
    """The refusal is printed once, and it is one line.

    The owner reads one line, and the line names the file that could
    not be read.
    """
    result, _ = run_program(
        step_zero_program(windows_script),
        tmp_path,
        policy_model(tmp_path, sysvolAccessDenied=True),
    )

    assert result.returncode != 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines.count(refusal()) == 1, result.stdout


def test_the_refusal_names_the_share_of_the_pdc(
    windows_script: str, tmp_path: Path
) -> None:
    """The refusal names the share of the PDC, and not the name of the
    domain.

    The share of the name of the domain may be served by another
    controller, and the policy of the PDC is not there.
    """
    result, _ = run_program(
        step_zero_program(windows_script),
        tmp_path,
        policy_model(tmp_path, sysvolAccessDenied=True),
    )

    assert result.returncode != 0
    assert GPT_INI_PATH in result.stdout, result.stdout
    assert f"\\\\{DOMAIN}\\SYSVOL" not in result.stdout


def test_the_constant_of_the_refusal_is_named_for_the_policy_backup() -> None:
    """The constant of the refusal is named after what it now means.

    It is not the refusal of a session that cannot read the share of
    the PDC any more: it is the refusal of a session that cannot back
    the policy of the PDC up.
    """
    from newton_mcp.ad import setupgen_write as write

    assert REFUSAL_HEAD + "{path}" + REFUSAL_TAIL == REFUSAL
    assert not hasattr(write, "NO_NETWORK_CREDENTIALS")
    assert not hasattr(write, "NO_PDC_SHARE")
    assert hasattr(write, "NO_POLICY_BACKUP")
    assert "{path}" in write.NO_POLICY_BACKUP
    assert write.NO_POLICY_BACKUP.replace("{path}", GPT_INI_PATH) == refusal()


# ---- the header and the comments ---------------------------------------------


def test_the_header_says_the_policy_is_edited_through_the_share_of_the_pdc(
    windows_script: str,
) -> None:
    """The header says the policy is edited through the share of the PDC."""
    header = comments(windows_script[: windows_script.index("Step 0:")])

    assert "edited in the share of the SYSVOL of the PDC" in header
    assert "the backup of it is made on the PDC" in header


def test_the_header_says_what_an_s4u_session_can_do(
    windows_script: str,
) -> None:
    """The header says what an S4U session can and cannot do.

    It holds no ticket of the domain, and the backup of the policy is
    unreliable over such a session.
    """
    header = comments(windows_script[: windows_script.index("Step 0:")])

    assert "S4U" in header
    assert "Backup-GPO" in header
    assert "E_ACCESSDENIED" in header
    assert "unreliable" in header


def test_the_header_says_the_share_of_the_domain_name_may_be_another_controller(
    windows_script: str,
) -> None:
    """The header says the share of the name of the domain may be served
    by another controller."""
    header = comments(windows_script[: windows_script.index("Step 0:")])

    assert (
        "the share of the name of the domain may be served by another controller"
        in header
    )


def test_the_header_does_not_say_that_a_key_login_cannot_edit_the_policy(
    windows_script: str,
) -> None:
    """No comment of the script says that a key login cannot back the
    policy up and cannot edit it.

    The later measurement says that the backup of the policy is
    unreliable over such a session, and not that it is always refused.
    """
    for phrase in GONE:
        assert phrase not in comments(windows_script), phrase


def test_the_comment_of_the_step_0_says_the_measured_rule(
    windows_script: str,
) -> None:
    """The comment of the pre-check says the measured rule.

    The step 0 reads the GPT.INI of the policy through the share of the
    PDC and backs the policy up, and the backup is unreliable over an
    S4U session: the read does not promise it.
    """
    said = comments(step_text(windows_script, 0))

    assert "S4U" in said
    assert "Backup-GPO" in said
    assert "E_ACCESSDENIED" in said
    assert "does not promise" in said
    assert "the share of the SYSVOL of the PDC" in said
    assert "the share of the name of the domain is not that one" in said


def test_the_script_says_nothing_about_a_key_login_that_cannot_work(
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


def test_the_measured_document_carries_the_new_run() -> None:
    """The measured document holds the run of this fix.

    It keeps the earlier failing measurement, and it says why it
    failed: the share of the name of the domain was served by the
    other controller.
    """
    text = MEASURED.read_text(encoding="utf-8")
    start = text.index("## Windows setup, measured 2026-11-09, sixth run")
    section = text[start:]

    assert "Cannot find path" in section
    assert "WSBXDC2.win2.newton.test" in section
    assert "the controller it runs on" in section
