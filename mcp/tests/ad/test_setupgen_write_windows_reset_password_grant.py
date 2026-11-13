"""A user-create with a secret needs the right of a password reset.

The write helper (with the append-only transaction store, and a hand fix
of its collection index leak) was driven on the real Server 2025 PDC ``WSBXDC1.win2.newton.test``,
under the delegation that the setup script grants.

- A ``user-create`` WITHOUT a secret answered ``ok``.  The user was
  created disabled (514), and the abort deleted it.
- A ``user-create`` WITH a secret answered ``denied``: LDAP result 50.
  Nothing was created.
- **The cause.**  Setting ``unicodePwd`` in the LDAP add is checked as
  the right of a password reset, ``00299570-246d-11d0-a768-00aa006e0529``,
  and the setup grants only ``CCDC;user`` on the OU.
- **The measured fix.**  On ``OU=NewtonOps`` this ran:
  ``dsacls <OU> /I:S /G "S-1-3-0:CA;Reset Password;user"`` (S-1-3-0 is
  CREATOR OWNER).  ``GetAccessRules`` then showed the rights
  ``ExtendedRight``, the object type
  ``00299570-246d-11d0-a768-00aa006e0529``, the inherited object type
  ``bf967aba-0de6-11d0-a285-00aa003049e2`` (the class ``user``), the
  inheritance ``Descendents`` and the trustee ``S-1-3-0``.  After that
  a ``user-create`` WITH a secret answered ``ok``.
- **The measured scope.**  On the existing users ``seed-plain`` and
  ``seed-asrep`` (owner Domain Admins) the inherited entry is
  ``S-1-3-0`` itself, and newton-ops holds NO Reset Password on them.
  Only an account that newton-ops creates gets the right, for its
  creator.

The right is granted to CREATOR OWNER and not to newton-ops: an
account that holds it directly could reset the password of any user of
the location, and a password reset is a change Newton never makes
itself (SPEC-1.4 section 1).

Every test here runs the generated PowerShell under the PowerShell of
this machine against a fake of Active Directory whose answers are the
measured ones.  The helpers of these tests are in ``windows_run.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad import setupgen_write as write
from windows_run import (
    AD_FAKE,
    BACKUP_ROOT_LINE,
    CREATOR_OWNER_SID,
    DOMAIN_DN,
    GUID_MACHINE_ACCOUNT_QUOTA,
    GUID_RESET_PASSWORD,
    GUID_USER,
    OPS_SID,
    OU,
    PUBLIC_KEY,
    RESET_PASSWORD_RIGHT,
    ZERO_GUID,
    delegation_program,
    fake_model,
    powershell_prelude,
    run_program,
    schema_guid,
    step_text,
    step_zero_without_the_elevation_check,
)


REPO_ROOT = Path(__file__).resolve().parents[3]

#: The contract of the write path.  Its section 9 holds the measured
#: facts of the two platforms.
SPEC = REPO_ROOT / "docs" / "proposals" / "ad" / "SPEC-1.4-REQUEST.md"

#: The name of the class of the objects the right of a password reset
#: is inherited to.
USER_CLASS = "user"


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


def delegated_rules() -> list[dict[str, Any]]:
    """The twelve rules the delegation grants, as the fake stores them.

    They are the rules of the measured run: ten
    property rights, the create-child and delete-child right of the
    user and of the computer objects, and nothing else.
    """
    rules: list[dict[str, Any]] = []
    for attribute, klass in write.DELEGATED_PROPERTIES:
        rules.append(
            {
                "sid": OPS_SID,
                "rights": "WriteProperty",
                "objectType": schema_guid(attribute),
                "inheritedObjectType": schema_guid(klass),
                "inheritanceType": "Descendents",
                "objectFlags": 3,
            }
        )
    for klass in ("user", "computer"):
        rules.append(
            {
                "sid": OPS_SID,
                "rights": "CreateChild, DeleteChild",
                "objectType": schema_guid(klass),
                "inheritedObjectType": ZERO_GUID,
                "inheritanceType": "All",
                "objectFlags": 1,
            }
        )
    return rules


def reset_rule(
    sid: str, object_type: str = GUID_RESET_PASSWORD, inherited: bool = False
) -> dict[str, Any]:
    """A rule of the right of a password reset."""
    rule = {
        "sid": sid,
        "rights": "ExtendedRight",
        "objectType": object_type,
        "inheritedObjectType": ZERO_GUID,
        "inheritanceType": "None",
        "objectFlags": 1,
    }
    if inherited:
        rule["inherited"] = True
    return rule


def quota_rule() -> dict[str, Any]:
    """The rule of the head of the domain: the machine account quota."""
    return {
        "sid": OPS_SID,
        "rights": "WriteProperty",
        "objectType": GUID_MACHINE_ACCOUNT_QUOTA,
        "inheritedObjectType": ZERO_GUID,
        "inheritanceType": "None",
        "objectFlags": 1,
    }


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
    model = fake_model(policyDir=str(policy))
    model.update(overrides)
    return model


def guard_program(script: str) -> str:
    """Run through step 1, including the effective-rights guard."""
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


# ---- the grant ---------------------------------------------------------------


def test_the_grant_is_the_measured_dsacls_call(
    windows_script: str, tmp_path: Path
) -> None:
    """The grant is the measured call.

    ``dsacls <OU> /I:S /G "S-1-3-0:CA;Reset Password;user"``: the right
    of a password reset, inherited by the descendants of the location,
    for the CREATOR OWNER.
    """
    result, recorded = run_program(
        delegation_program(windows_script), tmp_path, fake_model()
    )

    assert result.returncode == 0, result.stdout + result.stderr
    wanted = [
        OU,
        "/I:S",
        "/G",
        f"{CREATOR_OWNER_SID}:CA;{RESET_PASSWORD_RIGHT};{USER_CLASS}",
    ]
    assert wanted in recorded["dsacls"], recorded["dsacls"]


def test_the_trustee_is_the_creator_owner(
    windows_script: str, tmp_path: Path
) -> None:
    """The trustee of the grant is the CREATOR OWNER, and not newton-ops.

    A grant to newton-ops would let it reset the password of any user
    of the location, and a password reset is a change Newton never
    makes itself.
    """
    result, recorded = run_program(
        delegation_program(windows_script), tmp_path, fake_model()
    )

    assert result.returncode == 0, result.stdout + result.stderr
    grants = [
        call
        for call in recorded["dsacls"]
        if RESET_PASSWORD_RIGHT in call[-1]
    ]
    assert len(grants) == 1, grants
    assert grants[0][-1].startswith(CREATOR_OWNER_SID + ":")
    assert not grants[0][-1].startswith(OPS_SID)
    # The script builds the ace with the SID of the CREATOR OWNER, and
    # the SID of the write account is never the trustee of that right.
    assert f"$ace = $CreatorOwnerSid + ':CA;'" in windows_script


def test_the_read_back_holds_the_five_measured_fields(
    windows_script: str, tmp_path: Path
) -> None:
    """The read-back of the grant holds the five fields of the measure.

    The rights ``ExtendedRight``, the object type
    ``00299570-246d-11d0-a768-00aa006e0529``, the inherited object
    type ``bf967aba-0de6-11d0-a285-00aa003049e2``, the inheritance
    ``Descendents`` and the trustee ``S-1-3-0``.
    """
    result, recorded = run_program(
        delegation_program(windows_script), tmp_path, fake_model()
    )

    assert result.returncode == 0, result.stdout + result.stderr
    rules = [
        rule
        for rule in recorded["rules"][OU]
        if rule["sid"] == CREATOR_OWNER_SID
    ]
    assert len(rules) == 1, rules
    rule = rules[0]
    assert rule["rights"] == "ExtendedRight"
    assert rule["objectType"] == GUID_RESET_PASSWORD
    assert rule["inheritedObjectType"] == GUID_USER
    assert rule["inheritanceType"] == "Descendents"


def test_the_count_of_the_aces_of_the_location_is_thirteen(
    windows_script: str, tmp_path: Path
) -> None:
    """The location holds thirteen aces: the twelve of the delegation
    and the one of the CREATOR OWNER."""
    result, recorded = run_program(
        delegation_program(windows_script), tmp_path, fake_model()
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert len(recorded["rules"][OU]) == 13
    # The head of the domain holds its own ace and nothing else.
    assert len(recorded["rules"][DOMAIN_DN]) == 1


def test_the_new_row_is_the_only_grant_that_is_missing(
    windows_script: str, tmp_path: Path
) -> None:
    """The twelve aces of the delegation are there, and the only grant
    the script makes is the one of the CREATOR OWNER."""
    model = fake_model(
        acl={OU: delegated_rules(), DOMAIN_DN: [quota_rule()]}
    )

    result, recorded = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr
    assert recorded["dsacls"] == [
        [
            OU,
            "/I:S",
            "/G",
            f"{CREATOR_OWNER_SID}:CA;{RESET_PASSWORD_RIGHT};{USER_CLASS}",
        ]
    ]


def test_a_grant_that_is_already_there_is_not_granted_again(
    windows_script: str, tmp_path: Path
) -> None:
    """The ace of the CREATOR OWNER that is already there is read, field
    by field, and not granted again."""
    model = fake_model(
        acl={
            OU: delegated_rules()
            + [
                {
                    "sid": CREATOR_OWNER_SID,
                    "rights": "ExtendedRight",
                    "objectType": GUID_RESET_PASSWORD,
                    "inheritedObjectType": GUID_USER,
                    "inheritanceType": "Descendents",
                    "objectFlags": 3,
                }
            ],
            DOMAIN_DN: [quota_rule()],
        }
    )

    result, recorded = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr
    assert recorded["dsacls"] == []


def test_a_grant_that_does_not_land_is_a_refusal(
    windows_script: str, tmp_path: Path
) -> None:
    """A grant that is not there after it was made is a refusal.

    The descriptor is read back the way it was read on the real DC: with the
    rules of the object, and not with the SDDL text.
    """
    model = fake_model(
        acl={OU: delegated_rules(), DOMAIN_DN: [quota_rule()]},
        dsaclsWorks=False,
    )

    result, _ = run_program(delegation_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert f"{CREATOR_OWNER_SID}:CA;{RESET_PASSWORD_RIGHT};{USER_CLASS}" in output
    assert "is not there after the grant" in output


def test_the_guid_of_the_right_is_read_from_the_directory(
    windows_script: str,
) -> None:
    """The GUID of the right is read from the extended rights of the
    domain.

    The GUID that the script uses is the one the directory answered.
    Since the lookup of the right by its name, the GUID is also typed in the script, as the value the
    directory is checked against, and the read one is refused unless it
    is that value.
    """
    assert GUID_RESET_PASSWORD in windows_script
    assert "Get-ResetPasswordGuid" in windows_script
    assert "CN=Extended-Rights,CN=Configuration," in windows_script


# ---- the guard ---------------------------------------------------------------


def test_the_guard_runs_after_account_creation(windows_script: str) -> None:
    """The guard runs on every run after step 1 and before delegation."""
    account = step_text(windows_script, 1)
    assert "Test-NoResetPasswordRight" in account
    # The guard reads the rules of the objects and it grants nothing.
    # The rules of the location are read with the inherited ones, and
    # the rules of the objects below it are the explicit ones.
    assert "GetAccessRules($true, $false" in windows_script
    assert "GetAccessRules($false, $true" in windows_script
    call = windows_script.index("Test-NoResetPasswordRight", windows_script.index("Step 1:"))
    assert windows_script.index("Step 1:") < call < windows_script.index("Step 2:")


def test_an_empty_token_groups_read_is_a_refusal(
    windows_script: str, tmp_path: Path
) -> None:
    """An empty tokenGroups read fails closed on every run."""
    model = guard_model(tmp_path)
    model["users"][0]["tokenGroups"] = []

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "groups of newton-ops could not be read" in output


def test_the_first_run_creates_then_checks_effective_rights(
    windows_script: str, tmp_path: Path
) -> None:
    """A first run cannot skip the guard merely because the account was absent."""
    model = guard_model(
        tmp_path,
        users=[],
        acl={OU: [reset_rule("S-1-1-0")]},
    )

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "newton-ops was created with a random password" in output
    assert "effective right of a password reset" in output


def test_an_inherited_right_of_everyone_on_the_location_is_refused(
    windows_script: str, tmp_path: Path
) -> None:
    """A right that the location inherits is a right that it holds.

    The rules of the delegated location are read with the inherited
    ones: a right that the location inherits from the domain is a
    right of the location.
    """
    model = guard_model(
        tmp_path,
        acl={OU: [reset_rule("S-1-1-0", inherited=True)]},
    )

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "effective right of a password reset" in output
    assert OU in output


def test_an_inherited_right_on_an_object_is_not_counted(
    windows_script: str, tmp_path: Path
) -> None:
    """The rules of an object below the location are the explicit ones.

    The right that the setup grants itself is a CREATOR OWNER rule that
    the objects of the location inherit, and the trustee of that rule
    is not the write account: the rules that an object inherits are not
    the rules of that object.
    """
    child = "CN=seed-plain," + OU
    model = guard_model(
        tmp_path,
        acl={child: [reset_rule("S-1-1-0", inherited=True)]},
    )
    model["objects"].append(
        {"dn": child, "objectClass": ["top", "person", "organizationalPerson", "user"]}
    )

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "no effective right of a password reset" in result.stdout


@pytest.mark.parametrize(
    ("trustee", "rights", "object_type"),
    [
        ("S-1-5-21-1-2-3-513", "ExtendedRight", GUID_RESET_PASSWORD),
        ("S-1-1-0", "ExtendedRight", GUID_RESET_PASSWORD),
        ("S-1-5-11", "ExtendedRight", ZERO_GUID),
        ("S-1-5-11", "GenericAll", ZERO_GUID),
    ],
)
def test_effective_reset_rights_are_refused(
    windows_script: str,
    tmp_path: Path,
    trustee: str,
    rights: str,
    object_type: str,
) -> None:
    """Token groups and well-known groups are part of the trustee set."""
    model = guard_model(
        tmp_path,
        acl={OU: [reset_rule(trustee, object_type=object_type) | {"rights": rights}]},
    )

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    assert OU in result.stdout + result.stderr


def test_an_account_that_holds_the_right_on_the_location_is_refused(
    windows_script: str, tmp_path: Path
) -> None:
    """newton-ops may not hold the right of a password reset on the
    location."""
    model = guard_model(tmp_path, acl={OU: [reset_rule(OPS_SID)]})

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "Reset Password" in output or "password reset" in output
    assert OU in output


def test_an_inherited_right_on_the_location_is_refused(
    windows_script: str, tmp_path: Path
) -> None:
    """A right that the location INHERITS is a right that it holds.

    The rules of the location are read with the inherited ones, so a
    grant that the location inherits from its parent is a refusal too.
    """
    rule = reset_rule(OPS_SID)
    rule["inherited"] = True
    model = guard_model(tmp_path, acl={OU: [rule]})

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert OU in output


def test_an_account_that_holds_the_right_on_an_object_below_is_refused(
    windows_script: str, tmp_path: Path
) -> None:
    """newton-ops may not hold the right of a password reset on an
    object below the location either."""
    child = f"CN=seed-plain,{OU}"
    model = guard_model(
        tmp_path,
        objects=[
            *fake_model()["objects"],
            {"dn": child, "objectClass": ["user"]},
        ],
        acl={child: [reset_rule(OPS_SID)]},
    )

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert OU in output


def test_the_right_of_the_creator_of_an_object_is_not_a_refusal(
    windows_script: str, tmp_path: Path
) -> None:
    """The right of an object that newton-ops created is not a refusal.

    The grant is to the CREATOR OWNER, and the CREATOR OWNER of an
    object that newton-ops creates is newton-ops itself.  That is the
    scope of the grant: the write account may set the password of the
    accounts it creates, and of no other account.
    """
    child = f"CN=new-user,{OU}"
    rule = reset_rule(OPS_SID)
    rule["inherited"] = True
    model = guard_model(
        tmp_path,
        objects=[
            *fake_model()["objects"],
            {"dn": child, "objectClass": ["user"]},
        ],
        acl={child: [rule]},
    )

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr


def test_the_right_of_another_account_is_not_a_refusal(
    windows_script: str, tmp_path: Path
) -> None:
    """The right of the CREATOR OWNER is not a refusal: that is the
    grant of the delegation itself."""
    model = guard_model(
        tmp_path,
        acl={
            OU: [
                {
                    "sid": CREATOR_OWNER_SID,
                    "rights": "ExtendedRight",
                    "objectType": GUID_RESET_PASSWORD,
                    "inheritedObjectType": GUID_USER,
                    "inheritanceType": "Descendents",
                    "objectFlags": 3,
                }
            ]
        },
    )

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr


def test_an_account_that_holds_another_right_is_not_a_refusal(
    windows_script: str, tmp_path: Path
) -> None:
    """A right that is not the right of a password reset is not a
    refusal."""
    model = guard_model(
        tmp_path,
        acl={OU: [reset_rule(OPS_SID, object_type=GUID_USER)]},
    )

    result, _ = run_program(guard_program(windows_script), tmp_path, model)

    assert result.returncode == 0, result.stdout + result.stderr


# ---- the docs ----------------------------------------------------------------


def test_the_header_lists_the_new_row(windows_script: str) -> None:
    """The header of the script lists the new row, and why it is the
    CREATOR OWNER."""
    header = windows_script[: windows_script.index("Step 0:")]
    assert "CREATOR OWNER" in header
    assert CREATOR_OWNER_SID in header
    assert RESET_PASSWORD_RIGHT in header
    assert "the accounts it creates" in header
    assert "never makes itself" in header


def test_the_spec_lists_the_new_row() -> None:
    """The section 9 of the contract holds the row, and why it is the
    CREATOR OWNER."""
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("## 9.")
    end = text.find("\n## ", start + 1)
    section = text[start:] if end < 0 else text[start:end]
    assert RESET_PASSWORD_RIGHT in section
    assert "CREATOR OWNER" in section
    assert CREATOR_OWNER_SID in section
    assert GUID_RESET_PASSWORD in section
    rows = [
        line
        for line in section.splitlines()
        if line.startswith("|") and RESET_PASSWORD_RIGHT in line
    ]
    assert rows, section


def test_the_samba_script_is_not_changed(samba_script: str) -> None:
    """The Samba script is not changed: the same user-create passed live
    on Samba 4.22.11 without the right."""
    assert RESET_PASSWORD_RIGHT not in samba_script
    assert CREATOR_OWNER_SID not in samba_script
    assert GUID_RESET_PASSWORD not in samba_script
