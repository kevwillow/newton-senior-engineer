"""The right of a password reset is found by its real name.

The change that granted the reset-password right was read again, and the extended right was measured on
the real Server 2025 DC ``WSBXDC1.win2.newton.test``:

    name=User-Force-Change-Password | cn=User-Force-Change-Password |
    displayName=Reset Password | rightsGuid=00299570-246d-11d0-a768-00aa006e0529 |
    dn=CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=win2,DC=newton,DC=test

and the lookup of the right by the display name found nothing at all:

    by name Reset Password: 0

- **The defect.**  ``Get-ExtendedRightGuid $ExtendedRightsDn 'Reset
  Password'`` compares the ``name`` of the object with the display
  name, and the name of the object is its CN.  The run of the setup
  stops in the step 0 (the guard, once newton-ops exists) and in the
  step 2 (the grant).
- **Why the tests passed.**  The model of the fake held the right as
  ``CN=Reset Password`` with the name "Reset Password": that shape is
  invented, and the real object is the one of the measure.
- **What stays the same.**  The ace of ``dsacls``,
  ``S-1-3-0:CA;Reset Password;user``, carries the DISPLAY name, and
  that form was measured to work.

Every test here runs the generated PowerShell under the PowerShell of
this machine against a fake of Active Directory whose answers are the
measured ones.  The helpers of these tests are in ``windows_run.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from windows_run import (
    AD_FAKE,
    BACKUP_ROOT_LINE,
    CREATOR_OWNER_SID,
    EXTENDED_RIGHTS_DN,
    GUID_RESET_PASSWORD,
    OU,
    RESET_PASSWORD_RIGHT,
    RESET_PASSWORD_RIGHT_CN,
    delegation_program,
    fake_model,
    powershell_function,
    powershell_prelude,
    run_program,
    step_text,
    step_zero_without_the_elevation_check,
)


REPO_ROOT = Path(__file__).resolve().parents[3]

#: The name of the class of the objects the right of a password reset
#: is inherited to.
USER_CLASS = "user"


def right_object(**overrides: Any) -> dict[str, Any]:
    """The object of the extended right, with the fields of the measure.

    The name of the object is its CN, the display name is the one the
    directory shows, and the GUID is the one of the right.  A field may
    be replaced, to model a domain that holds another right.
    """
    built: dict[str, Any] = {
        "dn": f"CN={RESET_PASSWORD_RIGHT_CN},{EXTENDED_RIGHTS_DN}",
        "objectClass": ["controlAccessRight"],
        "name": RESET_PASSWORD_RIGHT_CN,
        "cn": RESET_PASSWORD_RIGHT_CN,
        "displayName": RESET_PASSWORD_RIGHT,
        "rightsGuid": GUID_RESET_PASSWORD,
    }
    built.update(overrides)
    return built


def model_with_right(right: dict[str, Any]) -> dict[str, Any]:
    """The model of the domain, with one right of a password reset."""
    model = fake_model()
    model["objects"] = [
        obj
        for obj in model["objects"]
        if "controlAccessRight" not in (obj.get("objectClass") or [])
    ]
    model["objects"].append(right)
    return model


def guard_model(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    """The model of the domain, with the share of the PDC readable.

    The step 0 reads the ``GPT.INI`` of the policy of the PDC,
    so the model of the guard has a folder that stands for the share.
    """
    policy = tmp_path / "policy"
    machine = policy / "Machine" / "Microsoft" / "Windows NT" / "SecEdit"
    machine.mkdir(parents=True)
    (policy / "GPT.INI").write_text("[General]\r\nVersion=7\r\n", encoding="ascii")
    (machine / "GptTmpl.inf").write_bytes(b"[Unicode]\r\nUnicode=yes\r\n")
    model = model_with_right(right_object())
    model["policyDir"] = str(policy)
    model.update(overrides)
    return model


def guard_program(script: str) -> str:
    """The program that runs through the effective-rights guard."""
    return "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f". '{AD_FAKE}'",
            powershell_prelude(script),
            "function Test-NoReplicationRight { param([string]$Sid, [string[]]$GroupSids) }",
            BACKUP_ROOT_LINE,
            step_zero_without_the_elevation_check(script),
            step_text(script, 1),
            "@{ calls = @($script:FakeCalls); rules = $script:FakeAclRules } |"
            " ConvertTo-Json -Depth 8 |"
            " Set-Content -LiteralPath $env:NEWTON_FAKE_OUT -Encoding utf8",
        ]
    )


# ---- the lookup --------------------------------------------------------------


def test_the_right_is_found_by_its_cn(
    windows_script: str, tmp_path: Path
) -> None:
    """The right of a password reset is found by its CN.

    The name of the object is its CN, ``User-Force-Change-Password``,
    and the display name is the one the directory shows.  A lookup by
    the display name finds nothing at all, and the grant of the step 2
    never happens.
    """
    result, recorded = run_program(
        delegation_program(windows_script), tmp_path, model_with_right(right_object())
    )

    assert result.returncode == 0, result.stdout + result.stderr
    wanted = [
        OU,
        "/I:S",
        "/G",
        f"{CREATOR_OWNER_SID}:CA;{RESET_PASSWORD_RIGHT};{USER_CLASS}",
    ]
    assert wanted in recorded["dsacls"], recorded["dsacls"]


def test_the_script_carries_the_three_measured_strings(
    windows_script: str,
) -> None:
    """The script carries the three strings of the measure.

    The CN, the display name and the GUID of the right, and nothing
    else: the lookup is by the CN, and the object is checked against
    the display name and the GUID before its GUID is used.
    """
    assert RESET_PASSWORD_RIGHT_CN in windows_script
    assert RESET_PASSWORD_RIGHT in windows_script
    assert GUID_RESET_PASSWORD in windows_script


def test_the_lookup_carries_the_three_constants(
    windows_script: str,
) -> None:
    """The lookup of the right carries the three strings of the measure.

    The CN is the key of the lookup, the display name and the GUID are
    the values the object is checked against.  The old lookup, the one
    that compared the name of the object with the display name, is
    gone.
    """
    function = powershell_function(windows_script, "Get-ResetPasswordGuid")
    assert RESET_PASSWORD_RIGHT_CN in function
    assert RESET_PASSWORD_RIGHT in function
    assert GUID_RESET_PASSWORD in function
    assert "Get-ExtendedRightGuid" not in windows_script


def test_a_right_with_another_display_name_is_refused(
    windows_script: str, tmp_path: Path
) -> None:
    """A right whose display name is not the measured one is refused.

    The object that carries the CN of the right of a password reset
    has to carry the display name "Reset Password" as well, or it is
    not the right the script is looking for.
    """
    model = model_with_right(right_object(displayName="Force change the password"))

    result, _ = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "display name" in output


def test_a_right_with_another_guid_is_refused(
    windows_script: str, tmp_path: Path
) -> None:
    """A right whose GUID is not the measured one is refused.

    The GUID of the right of a password reset is the one
    measured on the real DC, and a right with another GUID is not that right.
    """
    model = model_with_right(
        right_object(rightsGuid="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
    )

    result, _ = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "GUID" in output
    assert GUID_RESET_PASSWORD in output


def test_a_right_that_is_not_there_is_refused(
    windows_script: str, tmp_path: Path
) -> None:
    """A domain that holds no right of a password reset is refused.

    The refusal names the CN of the right, so the owner reads what the
    script looked for.
    """
    model = fake_model()
    model["objects"] = [
        obj
        for obj in model["objects"]
        if "controlAccessRight" not in (obj.get("objectClass") or [])
    ]

    result, _ = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert RESET_PASSWORD_RIGHT_CN in output
def test_the_guard_after_step_1_refuses_a_right_that_is_not_there(
    windows_script: str, tmp_path: Path
) -> None:
    """The guard after account creation reads and validates the right.

    The read is a refusal when the domain holds no such right, before
    the delegation step changes anything.
    """
    model = guard_model(tmp_path)
    model["objects"] = [
        obj
        for obj in model["objects"]
        if "controlAccessRight" not in (obj.get("objectClass") or [])
    ]

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert RESET_PASSWORD_RIGHT_CN in output


def test_the_ace_of_dsacls_carries_the_display_name(
    windows_script: str, tmp_path: Path
) -> None:
    """The ace of dsacls carries the DISPLAY name, and it did not change.

    ``dsacls <OU> /I:S /G "S-1-3-0:CA;Reset Password;user"`` is the
    form measured to work.  The lookup of the GUID
    is by the CN, and the ace is by the display name.
    """
    result, recorded = run_program(
        delegation_program(windows_script), tmp_path, model_with_right(right_object())
    )

    assert result.returncode == 0, result.stdout + result.stderr
    wanted = [
        OU,
        "/I:S",
        "/G",
        f"{CREATOR_OWNER_SID}:CA;{RESET_PASSWORD_RIGHT};{USER_CLASS}",
    ]
    assert wanted in recorded["dsacls"], recorded["dsacls"]
    assert RESET_PASSWORD_RIGHT_CN not in wanted[-1]


# ---- the fake ----------------------------------------------------------------


def test_the_model_holds_the_measured_right() -> None:
    """The model of the fake holds the right as it was measured.

    The dn of the real controller, the name of the object and its CN,
    the display name and the GUID.
    """
    rights = [
        obj
        for obj in fake_model()["objects"]
        if "controlAccessRight" in (obj.get("objectClass") or [])
    ]
    assert len(rights) == 1, rights
    right = rights[0]
    assert right["dn"] == (
        f"CN={RESET_PASSWORD_RIGHT_CN},{EXTENDED_RIGHTS_DN}"
    ), right["dn"]
    assert right["name"] == RESET_PASSWORD_RIGHT_CN
    assert right["cn"] == RESET_PASSWORD_RIGHT_CN
    assert right["displayName"] == RESET_PASSWORD_RIGHT
    assert right["rightsGuid"] == GUID_RESET_PASSWORD


def test_a_model_with_only_a_right_named_reset_password_is_refused(
    windows_script: str, tmp_path: Path
) -> None:
    """A model that holds only a right named "Reset Password" refuses.

    That is the shape the fake held before this fix, and it is
    invented: the real object is named by its CN.  A domain that holds
    that shape is refused, because the right of a password reset is not
    there.
    """
    model = model_with_right(
        right_object(
            dn=f"CN={RESET_PASSWORD_RIGHT},{EXTENDED_RIGHTS_DN}",
            name=RESET_PASSWORD_RIGHT,
            cn=RESET_PASSWORD_RIGHT,
            displayName=RESET_PASSWORD_RIGHT,
        )
    )

    result, _ = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert RESET_PASSWORD_RIGHT_CN in output
