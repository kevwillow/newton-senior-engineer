"""The parity of the two write helpers on the names of the accounts.

The Samba helper and the Windows helper answer a read with the same ids and
the same names.  The request schema of the contract accepts only a lowercase
name, so the name of a real account (``Administrator``) comes back in
lowercase from the two helpers, and the two compare the names without their
case.

The Windows helper is driven through the harness of ``win_write_harness.ps1``
and the fake directory of ``win_write_fake.ps1``.  The Samba helper is
loaded as a module and answers against the fake of ``fake_samba_write``.
No host is contacted.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

import fake_samba_write
from pwsh_path import PWSH
from test_samba_write_helper import Dc, dc


AD_DIR = Path(__file__).resolve().parent
HARNESS = AD_DIR / "win_write_harness.ps1"

#: The device names of the two helpers.
WINDOWS_DEVICE = "lab-win"
SAMBA_DEVICE = "lab-samba"

#: The domain of the Windows fake directory.
WINDOWS_DOMAIN_DN = "DC=win,DC=newton,DC=test"
WINDOWS_USERS_DN = f"OU=Users,{WINDOWS_DOMAIN_DN}"

#: The SID of the domain of the fixture: the Samba fake names it, and the
#: Windows fake holds the same one.
DOMAIN_SID = fake_samba_write.DOMAIN_SID

#: The account of the fixture, as both directories hold it.
ACCOUNT_GUID = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
ACCOUNT_SID = DOMAIN_SID + "-1105"
ACCOUNT_SAM = "Seed-Asrep"
ACCOUNT_REQUEST_SAM = "seed-asrep"

#: The group of the fixture.
GROUP_GUID = "8f9619ff-8b86-d011-b42d-00c04fc964ff"
GROUP_SID = DOMAIN_SID + "-1106"
GROUP_SAM = "Seed-Group"
GROUP_REQUEST_SAM = "seed-group"

#: The member of the fixture.
MEMBER_GUID = "9f9619ff-8b86-d011-b42d-00c04fc964ff"
MEMBER_SID = DOMAIN_SID + "-1107"
MEMBER_SAM = "Other-User"
MEMBER_REQUEST_SAM = "other-user"

#: The parent of a new user.
PARENT_GUID = "af9619ff-8b86-d011-b42d-00c04fc964ff"


def _windows_object(
    dn: str,
    guid: str | None = None,
    sid: str | None = None,
    sam: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """One object of the fake directory of the Windows helper."""
    entry: dict[str, Any] = {
        "dn": dn,
        "object_class": ["top", "person", "organizationalPerson", "user"],
        "uac": 512,
        "etypes": 0,
        "lockout": 0,
        "maq": None,
        "admin_count": 0,
        "member_of": [],
        "member": [],
        "primary_group_id": 513,
        "token_groups": ["S-1-5-21-1-2-3-513"],
        "parent": None,
        "usn_changed": 10,
        "delegated": True,
    }
    if guid is not None:
        entry["guid"] = guid
    if sid is not None:
        entry["sid"] = sid
    if sam is not None:
        entry["sam"] = sam
    entry.update(fields)
    return entry


def _windows_directory() -> dict[str, Any]:
    """The directory of the Windows fake, with the fixture of the parity."""
    return {
        "domain_dn": WINDOWS_DOMAIN_DN,
        "dns_domain": "win.newton.test",
        "service_name": "WINDC1.win.newton.test",
        "pdc": True,
        "objects": [
            _windows_object(
                f"CN={ACCOUNT_REQUEST_SAM},{WINDOWS_USERS_DN}",
                ACCOUNT_GUID,
                ACCOUNT_SID,
                ACCOUNT_SAM,
                uac=4194816,
            ),
            _windows_object(
                f"CN={GROUP_REQUEST_SAM},{WINDOWS_USERS_DN}",
                GROUP_GUID,
                GROUP_SID,
                GROUP_SAM,
                object_class=["top", "group"],
            ),
            _windows_object(
                f"CN={MEMBER_REQUEST_SAM},{WINDOWS_USERS_DN}",
                MEMBER_GUID,
                MEMBER_SID,
                MEMBER_SAM,
            ),
            _windows_object(
                WINDOWS_USERS_DN,
                PARENT_GUID,
                None,
                None,
                object_class=["top", "organizationalUnit"],
            ),
        ],
    }


def _samba_objects(dc: Dc) -> None:
    """The same fixture, in the directory of the Samba fake."""
    users = fake_samba_write.USERS_DN
    dc.fake.add_object(
        f"CN={ACCOUNT_SAM},{users}",
        {
            "objectClass": [b"user", b"person"],
            "sAMAccountName": [ACCOUNT_SAM.encode("utf-8")],
            "objectSid": [fake_samba_write.sid_bytes(ACCOUNT_SID)],
            "objectGUID": [fake_samba_write.guid_bytes(ACCOUNT_GUID)],
            "userAccountControl": [b"4194816"],
            "adminCount": [b"0"],
            "primaryGroupID": [b"513"],
            "memberOf": [fake_samba_write.DOMAIN_USERS_DN.encode("utf-8")],
            "uSNChanged": [b"2001"],
        },
    )
    dc.fake.add_object(
        f"CN={GROUP_SAM},{users}",
        {
            "objectClass": [b"group"],
            "sAMAccountName": [GROUP_SAM.encode("utf-8")],
            "objectSid": [fake_samba_write.sid_bytes(GROUP_SID)],
            "objectGUID": [fake_samba_write.guid_bytes(GROUP_GUID)],
            "adminCount": [b"0"],
            "primaryGroupID": [b"513"],
            "member": [],
            "uSNChanged": [b"2002"],
        },
    )
    dc.fake.add_object(
        f"CN={MEMBER_SAM},{users}",
        {
            "objectClass": [b"user", b"person"],
            "sAMAccountName": [MEMBER_SAM.encode("utf-8")],
            "objectSid": [fake_samba_write.sid_bytes(MEMBER_SID)],
            "objectGUID": [fake_samba_write.guid_bytes(MEMBER_GUID)],
            "userAccountControl": [b"512"],
            "adminCount": [b"0"],
            "primaryGroupID": [b"513"],
            "memberOf": [fake_samba_write.DOMAIN_USERS_DN.encode("utf-8")],
            "uSNChanged": [b"2003"],
        },
    )
    dc.fake.add_object(
        users,
        {
            "objectClass": [b"organizationalUnit"],
            "objectGUID": [fake_samba_write.guid_bytes(PARENT_GUID)],
            "uSNChanged": [b"2004"],
        },
    )


def _reads(device: str) -> dict[str, dict[str, Any]]:
    """The three reads of the fixture, for one of the two helpers."""
    return {
        "account": {
            "v": 1,
            "mode": "read",
            "device": device,
            "verb": "uac-clear",
            "target": {"sam": ACCOUNT_REQUEST_SAM},
        },
        "members": {
            "v": 1,
            "mode": "read",
            "device": device,
            "verb": "member-add",
            "target": {
                "group_sam": GROUP_REQUEST_SAM,
                "member_sam": MEMBER_REQUEST_SAM,
            },
        },
        "user-create": {
            "v": 1,
            "mode": "read",
            "device": device,
            "verb": "user-create",
            "target": {"parent_guid": PARENT_GUID, "sam": "new.user"},
        },
    }


@pytest.fixture(scope="module")
def windows_answers(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, dict[str, Any]]:
    """The answers of the Windows helper to the reads of the fixture."""
    if not PWSH.is_file():
        pytest.skip(f"PowerShell 7.4 is not installed at {PWSH}")
    directory = tmp_path_factory.mktemp("win-write-sam-parity")
    cases = [
        {
            "id": name,
            "ldap": _windows_directory(),
            "requests": [
                {
                    "raw": json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    "stage": "write",
                }
            ],
        }
        for name, payload in _reads(WINDOWS_DEVICE).items()
    ]
    cases_path = directory / "cases.json"
    cases_path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    finished = subprocess.run(
        [
            str(PWSH),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(HARNESS),
            str(cases_path),
        ],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if finished.returncode != 0:
        pytest.fail(
            "the harness of the Windows write helper failed: "
            f"{finished.returncode}: {finished.stderr.strip()[:2000]}"
        )
    document = json.loads(finished.stdout)
    return {str(case["id"]): case for case in document["cases"]}


@pytest.fixture
def samba_answers(dc: Dc) -> dict[str, dict[str, Any]]:
    """The answers of the Samba helper to the reads of the same fixture."""
    _samba_objects(dc)
    answers: dict[str, dict[str, Any]] = {}
    for name, payload in _reads(SAMBA_DEVICE).items():
        answers[name] = dc.run(payload)
    return answers


def test_the_two_helpers_answer_the_same_ids(
    windows_answers: dict[str, dict[str, Any]],
    samba_answers: dict[str, dict[str, Any]],
) -> None:
    """The ids of a read are the same in the two helpers."""
    for name in ("account", "members", "user-create"):
        windows = windows_answers[name]
        assert windows["code"] == "ok", name
        assert windows["error"] == "", name
        samba = samba_answers[name]
        assert samba["code"] == "ok", name
        assert set(windows["response"]["ids"]) == set(samba["ids"]), name
        assert windows["response"]["ids"] == samba["ids"], name


def test_every_name_of_the_ids_is_lowercase(
    windows_answers: dict[str, dict[str, Any]],
    samba_answers: dict[str, dict[str, Any]],
) -> None:
    """No name of an answer of the two helpers carries a capital."""
    for name in ("account", "members", "user-create"):
        for ids in (
            windows_answers[name]["response"]["ids"],
            samba_answers[name]["ids"],
        ):
            for key, value in ids.items():
                if not key.endswith("sam"):
                    continue
                assert isinstance(value, str), (name, key, value)
                assert value == value.lower(), (name, key, value)
