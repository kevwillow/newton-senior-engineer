"""Measured contract of the fake Windows directory; no host is contacted."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pwsh_path import PWSH


AD_DIR = Path(__file__).resolve().parent
PROBE = AD_DIR / "win_write_fake_contract.ps1"
FAKE = AD_DIR / "win_write_fake.ps1"


def _pwsh() -> str:
    if not PWSH.is_file():
        pytest.skip(f"PowerShell 7.4 is not installed at {PWSH}")
    return str(PWSH)


@pytest.fixture(scope="module")
def measured() -> dict[str, object]:
    finished = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(PROBE), str(FAKE)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr
    return json.loads(finished.stdout)


def test_search_returns_only_requested_lowercase_attributes(measured: dict[str, object]) -> None:
    assert measured["requested_keys"] == ["samaccountname"]
    assert measured["unrequested_sid_present"] is False


def test_empty_subtree_base_is_no_such_object(measured: dict[str, object]) -> None:
    assert measured["empty_subtree_code"] == 32


def test_binary_attributes_and_tokengroups_match_the_dc(measured: dict[str, object]) -> None:
    assert measured["sid_is_bytes"] is True
    assert measured["guid_is_bytes"] is True
    assert measured["token_count"] == 1
    assert measured["token_is_bytes"] is True
    assert measured["subtree_token_present"] is False


def test_directory_layout_matches_the_dc(measured: dict[str, object]) -> None:
    assert measured["ds_service_name"] == (
        "CN=NTDS Settings,CN=WSBXDC1,CN=Servers,"
        "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,"
        "DC=win,DC=newton,DC=test"
    )
    assert measured["ntds_has_dns"] is False
    assert "organizationalUnit" in measured["dc_ou_classes"]
    assert measured["dc_ou_has_parent"] is False
    assert measured["quota_keys"] == ["ms-ds-machineaccountquota"]


def test_the_domain_head_has_no_dns_domain_name(measured: dict[str, object]) -> None:
    """The domainDNS head of a real DC carries no dNSDomainName.

    Measured 2026-11-13 on WINDC1: a base read of the head asking for
    dNSDomainName answered adspath, name and objectguid only.
    """
    assert measured["head_dns_keys"] == []


def test_modify_and_modifydn_match_the_dc(measured: dict[str, object]) -> None:
    assert measured["modify_dn_code"] == 53
    assert measured["move_exists"] is True
    assert measured["move_again_code"] == 32


def test_the_member_filter_answers_the_presence_of_one_member(
    measured: dict[str, object],
) -> None:
    """The member filter of the fake answers the presence of one member."""
    assert measured["member_filter_found"] is True
    assert measured["member_filter_absent"] is True


def test_the_fake_holds_the_name_of_an_account_with_its_case(
    measured: dict[str, object],
) -> None:
    """The fake is honest: it answers the name with the case it holds."""
    assert measured["mixed_case_found"] is True
    assert measured["mixed_case_sam"] == "Administrator"


def test_the_fake_denies_writing_an_existing_store_file(
    measured: dict[str, object],
) -> None:
    """Write and ReadWrite need rights the account lacks."""
    assert measured["existing_write_unauthorized"] is True
    assert measured["existing_readwrite_unauthorized"] is True


def test_the_fake_allows_read_and_create_new_write(
    measured: dict[str, object],
) -> None:
    """The two operations measured to work stay available."""
    assert measured["existing_read_text"] == "old"
    assert measured["create_new_text"] == "new"


def test_the_fake_denies_replace_delete_and_move(
    measured: dict[str, object],
) -> None:
    """All three operations require DELETE under the ACL."""
    assert measured["replace_unauthorized"] is True
    assert measured["delete_unauthorized"] is True
    assert measured["move_unauthorized"] is True


def test_the_old_record_rewrite_fails_against_the_honest_fake(
    measured: dict[str, object],
) -> None:
    """The pre-fix temp/replace/delete/move algorithm is denied."""
    assert measured["old_record_write_unauthorized"] is True
    assert measured["old_record_text"] == "old"

