"""The forbidden-attribute list: the single source for both collectors."""

from __future__ import annotations

import json

from newton_mcp.ad import forbidden


def test_the_list_holds_every_name_the_spec_names() -> None:
    """The normative list of SPEC-1.3 section 4 is complete."""
    expected = {
        "unicodePwd",
        "dBCSPwd",
        "ntPwdHistory",
        "lmPwdHistory",
        "pwdHistory",
        "supplementalCredentials",
        "userPassword",
        "unixUserPassword",
        "msSFU30Password",
        "ms-Mcs-AdmPwd",
        "msLAPS-Password",
        "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRMPassword",
        "msLAPS-EncryptedDSRMPasswordHistory",
        "msFVE-RecoveryPassword",
        "msFVE-KeyPackage",
        "msFVE-RecoveryGuid",
        "msFVE-VolumeGuid",
        "msDS-ManagedPassword",
        "msDS-ManagedPasswordId",
        "msDS-ManagedPasswordPreviousId",
        "msKds-RootKeyData",
        "currentValue",
        "priorValue",
        "trustAuthIncoming",
        "trustAuthOutgoing",
        "initialAuthIncoming",
        "initialAuthOutgoing",
        "msPKI-DPAPIMasterKeys",
        "msPKI-CredentialRoamingTokens",
        "msPKIAccountCredentials",
        "msPKIRoamingTimeStamp",
        "msDS-KeyCredentialLink",
        # The first red-team review: the password names the spec does not name.
        "clearTextPassword",
        "pekList",
        "sambaNTPassword",
        "sambaLMPassword",
        "sambaPasswordHistory",
        "msDS-ExecuteScriptPassword",
    }

    assert forbidden.FORBIDDEN_ATTRIBUTES == frozenset(
        name.lower() for name in expected
    )
    assert all(name == name.lower() for name in forbidden.FORBIDDEN_ATTRIBUTES)


def test_the_deliberate_deltas_are_not_forbidden() -> None:
    """The spec keeps four names off the list, with a reason."""
    for name in (
        "nTSecurityDescriptor",
        "securityIdentifier",
        "sIDHistory",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ):
        assert forbidden.is_forbidden(name) is False


def test_a_forbidden_name_is_forbidden_whatever_its_case() -> None:
    """The comparison ignores case."""
    assert forbidden.is_forbidden("userPassword") is True
    assert forbidden.is_forbidden("USERPASSWORD") is True
    assert forbidden.is_forbidden("userpassword") is True


def test_the_options_of_an_attribute_name_do_not_hide_it() -> None:
    """A collector may add ";binary" or a range to a name."""
    assert forbidden.is_forbidden("userPassword;binary") is True
    assert forbidden.is_forbidden("msDS-KeyCredentialLink;binary") is True


def test_a_range_option_on_another_attribute_is_not_forbidden() -> None:
    """A ranged attribute that is not on the list stays allowed."""
    assert forbidden.is_forbidden("member;range=0-1500") is False
    assert forbidden.is_forbidden("member;range=*") is False


def test_something_that_is_not_an_attribute_name_is_not_forbidden() -> None:
    """The predicate is about names, not about arbitrary text."""
    assert forbidden.is_forbidden(None) is False
    assert forbidden.is_forbidden("") is False
    assert forbidden.is_forbidden(42) is False


def test_the_json_dump_is_the_sorted_list() -> None:
    """forbidden.json is a sorted JSON array of the names."""
    raw = forbidden.dump_json()

    assert isinstance(raw, bytes)
    assert raw.endswith(b"\n")
    decoded = json.loads(raw.decode("utf-8"))
    assert decoded == sorted(forbidden.FORBIDDEN_ATTRIBUTES)


def test_the_json_dump_is_the_same_every_time() -> None:
    """Two collectors get byte-identical files."""
    assert forbidden.dump_json() == forbidden.dump_json()


def test_the_password_names_of_the_red_team_are_on_the_list() -> None:
    """The names of the first red-team review are forbidden too."""
    for name in (
        "clearTextPassword",
        "pekList",
        "sambaNTPassword",
        "sambaLMPassword",
        "sambaPasswordHistory",
        "msDS-ExecuteScriptPassword",
    ):
        assert forbidden.is_forbidden(name) is True
        assert forbidden.is_forbidden(name.lower()) is True


def test_the_managed_password_names_stay_on_the_list() -> None:
    """The names the red team left alone are still there."""
    for name in (
        "msDS-ManagedPassword",
        "msDS-ManagedPasswordId",
        "msDS-ManagedPasswordPreviousId",
    ):
        assert forbidden.is_forbidden(name) is True
