"""The Windows setup reads the groups of the account with a base read.

The generated Windows setup ran on the real PDC
``WSBXDC1.win2.newton.test`` over the key login on 2026-11-09.  It
stopped right after the step 1:

    Get-ADUser : The requested search operation is only supported for base searches
        + FullyQualifiedErrorId : ActiveDirectoryServer:8480,Microsoft.ActiveDirectory.Management.Commands.GetADUser

The line was ``setupgen_write.py:773``::

    $opsUser = Get-ADUser -Identity $OpsName -Properties userAccountControl, tokenGroups

``tokenGroups`` is a constructed attribute, and the directory gives it
only to a read whose scope is Base.  The write helper of the Windows
platform already does it right (``write.ps1:1942`` reads the groups of
the account in a base search of the account itself).

The fake of the directory (``win_setup_fake.ps1``) models the rule: a
read of ``tokenGroups`` that is not a base search is refused with the
measured error, and only a ``Get-ADObject`` with ``-SearchScope Base``
is answered.

Every test here runs the generated PowerShell under the PowerShell of
this machine against that fake.  The helpers of these tests are in
``windows_run.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from windows_run import (
    AD_FAKE,
    BACKUP_ROOT_LINE,
    DOMAIN_DN,
    OU,
    fake_model,
    powershell_prelude,
    recorded_calls,
    run_program,
    step_text,
    step_zero_without_the_elevation_check,
)


#: The message the directory answers when the groups of an object are
#: asked for in a read that is not a base search.
REFUSAL = "The requested search operation is only supported for base searches"

#: The identifier of that error, the one read on the real PDC.
ERROR_ID = "ActiveDirectoryServer:8480"

#: The read of the account of the script before the account-read fix:
#: it asks for the groups of the account with a read that is not a
#: base search.
OLD_ACCOUNT_READ = (
    "$opsUser = Get-ADUser -Identity $OpsName -Properties userAccountControl, tokenGroups"
)

#: The read of the groups of the script before the account-read fix.
OLD_GROUP_READ = "$tokenProperty = $opsUser.PSObject.Properties['tokenGroups']"

#: The read of the account of the script of this tree.
NEW_ACCOUNT_READ = (
    "$opsUser = Get-ADUser -Identity $OpsName -Properties userAccountControl"
)

#: The read of the groups of the script of this tree: the scope is
#: Base, and the base is the account itself.
NEW_GROUP_READ = """$groupObjects = @(Get-ADObject -SearchBase $opsUser.DistinguishedName -SearchScope Base -Filter '*' -Properties tokenGroups)
$tokenProperty = $null
if ($groupObjects.Count -eq 1) {
    $tokenProperty = $groupObjects[0].PSObject.Properties['tokenGroups']
}"""


def script_before_the_account_read_fix(script: str) -> str:
    """The script before the account-read fix, out of the script of this tree.

    The two reads of the script before the account-read fix are put
    back, so the test runs the script that ran on the real PDC.  On the
    build before the account-read fix the script of this tree IS that
    script, and it is returned as it is.
    """
    if OLD_ACCOUNT_READ in script:
        return script
    rebuilt = script.replace(NEW_GROUP_READ, OLD_GROUP_READ)
    rebuilt = rebuilt.replace(NEW_ACCOUNT_READ, OLD_ACCOUNT_READ)
    return rebuilt


def group_read_model(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    """The model of the domain, with the share of the PDC readable.

    The step 0 reads the ``GPT.INI`` of the policy of the PDC, so the
    model has a folder that stands for the share.
    """
    policy = tmp_path / "policy"
    machine = policy / "Machine" / "Microsoft" / "Windows NT" / "SecEdit"
    machine.mkdir(parents=True)
    (policy / "GPT.INI").write_text("[General]\r\nVersion=7\r\n", encoding="ascii")
    (machine / "GptTmpl.inf").write_bytes(b"[Unicode]\r\nUnicode=yes\r\n")
    model = fake_model(policyDir=str(policy))
    model.update(overrides)
    return model


def group_read_program(script: str) -> str:
    """The program that runs the step 0 and the step 1 of the script."""
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            BACKUP_ROOT_LINE,
            step_zero_without_the_elevation_check(script),
            step_text(script, 1),
            "@{ calls = @($script:FakeCalls) } | ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )


# ---- the fake models the rule ------------------------------------------------


def test_the_fake_refuses_a_read_of_the_groups_that_is_not_a_base_search(
    tmp_path: Path,
) -> None:
    """The fake refuses every read of the groups that is not a base search.

    The directory gives the groups of an object only to a base search,
    and it refuses the other reads with the error 8480.  The fake
    answers a base search and refuses everything else.
    """
    program = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            f"$dn = 'CN=newton-ops,{OU}'",
            "$base = @(Get-ADObject -SearchBase $dn -SearchScope Base -Filter '*' -Properties tokenGroups)",
            "if ($base.Count -ne 1) { Write-Output 'the base search answered nothing'; exit 1 }",
            "$groups = @($base[0].PSObject.Properties['tokenGroups'].Value)",
            "if ($groups.Count -eq 0) { Write-Output 'the base search answered no group'; exit 1 }",
            "foreach ($call in @(",
            "  { Get-ADUser -Identity 'newton-ops' -Properties tokenGroups },",
            "  { Get-ADUser -Identity 'newton-ops' -Properties userAccountControl, tokenGroups },",
            "  { Get-ADObject -SearchBase $dn -SearchScope Subtree -Filter '*' -Properties tokenGroups },",
            "  { Get-ADObject -SearchBase $dn -SearchScope OneLevel -Filter '*' -Properties tokenGroups },",
            "  { Get-ADObject -Identity $dn -Properties tokenGroups }",
            ")) {",
            "  try {",
            "    $null = & $call",
            "    Write-Output 'a read that is not a base search was not refused'",
            "    exit 1",
            "  } catch {",
            "    if ($_.Exception.Message -notmatch 'only supported for base searches') {",
            "      Write-Output ('another error: ' + $_.Exception.Message)",
            "      exit 1",
            "    }",
            "    if ($_.FullyQualifiedErrorId -notmatch 'ActiveDirectoryServer:8480') {",
            "      Write-Output ('another identifier: ' + $_.FullyQualifiedErrorId)",
            "      exit 1",
            "    }",
            "  }",
            "}",
            "Write-Output 'ok'",
        ]
    )

    result, _ = run_program(program, tmp_path, group_read_model(tmp_path))

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "ok"


# ---- the script of this tree -------------------------------------------------


def test_the_script_asks_for_the_groups_only_in_a_base_search(
    windows_script: str,
) -> None:
    """Only one line of the script asks for the groups, and it is a base read.

    The line is a ``Get-ADObject`` whose scope is Base and whose base
    is the account of the write account, the way the write helper
    reads them (``write.ps1:1942``).
    """
    asks = [
        line.strip()
        for line in windows_script.splitlines()
        if "tokenGroups" in line
        and "Get-AD" in line
        and not line.strip().startswith("#")
    ]
    assert len(asks) == 1, asks
    assert "-SearchScope Base" in asks[0]
    assert "-Properties tokenGroups" in asks[0]
    assert "-SearchBase $opsUser.DistinguishedName" in asks[0]


def test_the_step_1_runs_against_the_stricter_fake(
    windows_script: str, tmp_path: Path
) -> None:
    """The step 1 of the script runs against the fake of the rule.

    The script before the account-read fix stopped here, with the
    error 8480 of the directory.  The script of this tree reads the
    groups with a base search, and the run goes on.
    """
    result, recorded = run_program(
        group_read_program(windows_script), tmp_path, group_read_model(tmp_path)
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert ERROR_ID not in output
    assert "Step 1: the newton-ops account" in result.stdout
    # The groups are read once, and they are read in a base search.
    reads = recorded_calls(recorded, "Get-ADObject")
    base = [
        read
        for read in reads
        if read.get("searchScope") == "Base"
        and "tokenGroups" in (read.get("properties") or [])
    ]
    assert len(base) == 1, reads
    assert base[0]["searchBase"] == f"CN=newton-ops,{OU}"
    # The account is never read with the groups.
    users = recorded_calls(recorded, "Get-ADUser")
    assert not [
        read for read in users if "tokenGroups" in (read.get("properties") or [])
    ], users


def test_an_empty_read_of_the_groups_is_a_refusal(
    windows_script: str, tmp_path: Path
) -> None:
    """An empty read of the groups refuses: an empty read is "could not read".

    Every account holds Domain Users: an empty list of groups is a
    refusal, never a pass.
    """
    model = group_read_model(tmp_path)
    model["users"][0]["tokenGroups"] = []

    result, _ = run_program(group_read_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    assert "groups of newton-ops could not be read" in (result.stdout + result.stderr)


def test_a_read_of_the_groups_that_answers_nothing_is_a_refusal(
    windows_script: str, tmp_path: Path
) -> None:
    """A read of the groups that answers nothing refuses."""
    model = group_read_model(tmp_path)
    del model["users"][0]["tokenGroups"]

    result, _ = run_program(group_read_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    assert "groups of newton-ops could not be read" in (result.stdout + result.stderr)


# ---- the script before the account-read fix ----------------------------------


def test_the_script_before_the_account_read_fix_stops_at_the_step_1_with_the_measured_error(
    windows_script: str, tmp_path: Path
) -> None:
    """The script before the account-read fix stops at the step 1 with the measured error.

    Its read of the groups asks for the groups of the account with a
    read that is not a base search, and the directory refuses it with
    the error 8480.  That is what the real
    controller answered, and the fake answers it the same way.
    """
    script = script_before_the_account_read_fix(windows_script)

    result, _ = run_program(group_read_program(script), tmp_path, group_read_model(tmp_path))

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert REFUSAL in output
    assert ERROR_ID in output
    # The run stops in the step 1, before any change.
    assert "Step 1: the newton-ops account" in result.stdout
    assert "Step 2:" not in result.stdout
