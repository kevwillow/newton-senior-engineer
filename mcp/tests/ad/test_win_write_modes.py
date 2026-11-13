"""The modes of the Windows write helper, against the fake directory.

The helper is driven through the harness of ``win_write_harness.ps1``: one
pwsh process, the fake LDAP adapter of ``win_write_fake.ps1`` and the fake
task scheduler.  The fake behaves the way the directory of the lab DC
behaves, as SPEC section 9 measured it: a stale old value is 16, a write
outside the delegation is 50 and an add with a unicodePwd works.

The tests are skipped, with a reason, when PowerShell 7.4 is not installed.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.write import request
from pwsh_path import PWSH


AD_DIR = Path(__file__).resolve().parent
HARNESS = AD_DIR / "win_write_harness.ps1"

#: The key of the tests (SPEC section 4).
KEY_HEX = "11" * 32

#: The ids of the domain of the tests.
DEVICE = "lab-win"
DOMAIN_DN = "DC=win,DC=newton,DC=test"
DNS_DOMAIN = "win.newton.test"
SERVICE_NAME = "WINDC1.win.newton.test"
#: A domain DN with a part that is not DC=: no DNS name comes from it.
ODD_DOMAIN_DN = "DC=win,O=odd,DC=test"
OU_USERS = f"OU=Users,{DOMAIN_DN}"
OU_OPS = f"OU=Ops,{DOMAIN_DN}"

#: The objects of the directory of the tests.
SEED_GUID = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
SEED_SID = "S-1-5-21-1-2-3-1105"
SEED_SAM = "seed-asrep"
GROUP_GUID = "8f9619ff-8b86-d011-b42d-00c04fc964ff"
GROUP_SID = "S-1-5-21-1-2-3-1106"
GROUP_SAM = "seed-group"
MEMBER_GUID = "9f9619ff-8b86-d011-b42d-00c04fc964ff"
MEMBER_SID = "S-1-5-21-1-2-3-1107"
MEMBER_SAM = "other-user"
OU_GUID = "bf9619ff-8b86-d011-b42d-00c04fc964ff"
OU_OPS_GUID = "1b9619ff-8b86-d011-b42d-00c04fc964ff"
DC_OU_GUID = "2f9619ff-8b86-d011-b42d-00c04fc964ff"
PARENT_GUID = "af9619ff-8b86-d011-b42d-00c04fc964ff"
OTHER_PARENT_GUID = "cf9619ff-8b86-d011-b42d-00c04fc964ff"
ADMINS_GUID = "df9619ff-8b86-d011-b42d-00c04fc964ff"
ADMINS_SID = "S-1-5-21-1-2-3-512"
ADMINS_DN = f"CN=Domain Admins,{DOMAIN_DN}"
NESTED_GUID = "ef9619ff-8b86-d011-b42d-00c04fc964ff"
NESTED_SID = "S-1-5-21-1-2-3-1110"
NESTED_DN = f"CN=nested-admins,{OU_USERS}"
CYCLE_GUID = "f09619ff-8b86-d011-b42d-00c04fc964ff"
CYCLE_SID = "S-1-5-21-1-2-3-1111"
CYCLE_DN = f"CN=cycle-one,{OU_USERS}"
CYCLE_DN_TWO = f"CN=cycle-two,{OU_USERS}"
OPS_GUID = "0a9619ff-8b86-d011-b42d-00c04fc964ff"
OPS_SID = "S-1-5-21-1-2-3-1100"

#: The GUID the fake gives BUILTIN Administrators (the fake's own id).
BUILTIN_ADMINS_GUID = "5b9619ff-8b86-d011-b42d-00c04fc964ff"

#: The administrator of the directory of the tests, as a real DC names it.
ADMIN_SAM = "Administrator"
ADMIN_GUID = "3f9619ff-8b86-d011-b42d-00c04fc964ff"
ADMIN_SID = "S-1-5-21-1-2-3-500"

#: The names the directory of the tests holds.  A real DC keeps the case of
#: the name the account was given (``Administrator``), and the request
#: schema accepts only a lowercase name: the helper answers with the name in
#: lowercase and compares the names without their case.
SEED_LIVE_SAM = "Seed-Asrep"
GROUP_LIVE_SAM = "Seed-Group"
MEMBER_LIVE_SAM = "Other-User"
LIVE_SAMS = {
    SEED_SAM: SEED_LIVE_SAM,
    GROUP_SAM: GROUP_LIVE_SAM,
    MEMBER_SAM: MEMBER_LIVE_SAM,
}

#: The clock of the tests.
NOW = 1800000000
NBF = 1800000000
EXP = 1800000600

#: The transaction id of the tests.
TXID = "0123456789abcdef0123456789abcdef"


def _object(
    dn: str,
    guid: str | None = None,
    sid: str | None = None,
    sam: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """One object of the fake directory."""
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
        # the directory holds the name as it was given, the way a real DC
        # holds it
        entry["sam"] = LIVE_SAMS.get(sam, sam)
    entry.update(fields)
    return entry


def _directory(**changes: Any) -> dict[str, Any]:
    """The directory of the tests."""
    omit_write_account = bool(changes.pop("omit_write_account", False))
    write_token_groups = changes.pop("write_token_groups", None)
    objects = [
        _object(
            f"CN=newton-ops,{OU_OPS}",
            OPS_GUID,
            OPS_SID,
            "newton-ops",
            token_groups=["S-1-5-21-1-2-3-513"],
        ),
        _object(
            f"CN={SEED_SAM},{OU_USERS}",
            SEED_GUID,
            SEED_SID,
            SEED_SAM,
            uac=4260352,
            parent=OU_USERS,
        ),
        _object(
            f"CN={GROUP_SAM},{OU_USERS}",
            GROUP_GUID,
            GROUP_SID,
            GROUP_SAM,
            object_class=["top", "group"],
            parent=OU_USERS,
        ),
        _object(
            f"CN={MEMBER_SAM},{OU_USERS}",
            MEMBER_GUID,
            MEMBER_SID,
            MEMBER_SAM,
            parent=OU_USERS,
        ),
        _object(
            OU_USERS,
            OU_GUID,
            None,
            None,
            object_class=["top", "organizationalUnit"],
        ),
        _object(
            OU_OPS,
            OU_OPS_GUID,
            None,
            None,
            object_class=["top", "organizationalUnit"],
        ),
        _object(
            ADMINS_DN,
            ADMINS_GUID,
            ADMINS_SID,
            "domain-admins",
            object_class=["top", "group"],
            parent=DOMAIN_DN,
        ),
        _object(
            f"CN={ADMIN_SAM},{DOMAIN_DN}",
            ADMIN_GUID,
            ADMIN_SID,
            ADMIN_SAM,
            admin_count=1,
            primary_group_id=512,
            parent=DOMAIN_DN,
        ),
    ]
    if write_token_groups is not None:
        objects[0]["token_groups"] = write_token_groups
    if omit_write_account:
        objects = objects[1:]
    if "objects" in changes:
        supplied = list(changes["objects"])
        if not omit_write_account and not any(
            entry.get("sam") == "newton-ops" for entry in supplied
        ):
            supplied.insert(0, objects[0])
        objects = supplied
        changes = {name: value for name, value in changes.items() if name != "objects"}
    config: dict[str, Any] = {
        "domain_dn": DOMAIN_DN,
        "dns_domain": DNS_DOMAIN,
        "service_name": SERVICE_NAME,
        "pdc": True,
        "objects": objects,
    }
    config.update(changes)
    return config


def _apply(
    verb: str = "uac-clear",
    target: dict[str, Any] | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    **changes: Any,
) -> str:
    """An apply request of the contract, with its own token."""
    if target is None:
        target = {"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM, "bit": 4194304}
    if before is None:
        before = {"uac": 4260352}
    if after is None:
        after = {"uac": 66048}
    payload: dict[str, Any] = {
        "v": 1,
        "mode": "apply",
        "device": DEVICE,
        "txid": TXID,
        "verb": verb,
        "target": target,
        "before": before,
        "after": after,
        "window": 600,
        "risk": "MED",
        "nbf": NBF,
        "exp": EXP,
    }
    payload.update(changes)
    if "token" not in changes:
        payload["token"] = request.token(
            KEY_HEX, request.digest(payload), payload["nbf"], payload["exp"]
        )
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _mode(mode: str, **changes: Any) -> str:
    """A request of one of the other modes."""
    payload: dict[str, Any] = {
        "v": 1,
        "mode": mode,
        "device": DEVICE,
        "txid": TXID,
    }
    payload.update(changes)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _stored_record(state: str, *, undo_at: int = NOW + 600) -> str:
    """One transaction record as the Windows helper stores it."""
    payload = json.loads(_apply())
    payload.pop("secret", None)
    payload.pop("token", None)
    return json.dumps(
        {
            "v": 1,
            "txid": TXID,
            "request": payload,
            "created": None,
            "state": state,
            "undo_at": undo_at,
            "restored": False,
            "conflicts": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _read(verb: str = "uac-clear", target: dict[str, Any] | None = None) -> str:
    """A read request of the contract."""
    if target is None:
        target = {"sam": SEED_SAM}
    return json.dumps(
        {
            "v": 1,
            "mode": "read",
            "device": DEVICE,
            "verb": verb,
            "target": target,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _move(before_parent: str = OU_GUID, after_parent: str = OU_OPS_GUID, **changes: Any) -> str:
    """An apply request of a move."""
    return _apply(
        "move",
        target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
        before={"parent": before_parent},
        after={"parent": after_parent},
        **changes,
    )


def _deep_groups(count: int) -> list[dict[str, Any]]:
    """A chain of groups deeper than the cap of the privilege walk."""
    groups = []
    for index in range(count):
        member_of = []
        if index + 1 < count:
            member_of = [f"CN=deep-{index + 1},{OU_USERS}"]
        groups.append(
            _object(
                f"CN=deep-{index},{OU_USERS}",
                f"d0{index:06x}-8b86-d011-b42d-00c04fc964ff",
                f"S-1-5-21-1-2-3-{1200 + index}",
                f"deep-{index}",
                object_class=["top", "group"],
                member_of=member_of,
                parent=OU_USERS,
            )
        )
    return groups


def _cases() -> list[dict[str, Any]]:
    """Every case of the modes."""
    cases: list[dict[str, Any]] = []

    def add(name: str, **fields: Any) -> None:
        cases.append({"id": name, **fields})

    # the read mode
    add("read-ok", ldap=_directory(), requests=[{"raw": _read(), "stage": "write"}])
    add(
        "read-not-found",
        ldap=_directory(),
        requests=[
            {
                "raw": _read(target={"sam": "no-such-user"}),
                "stage": "write",
            }
        ],
    )
    add(
        "read-two-matches",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                ),
                _object(
                    f"CN=other-{SEED_SAM},{OU_USERS}",
                    MEMBER_GUID,
                    MEMBER_SID,
                    SEED_SAM,
                    parent=OU_USERS,
                ),
            ]
        ),
        requests=[{"raw": _read(), "stage": "write"}],
    )

    # the names the directory holds in another case
    add(
        "read-mixed-case-account",
        ldap=_directory(),
        requests=[{"raw": _read(target={"sam": SEED_SAM}), "stage": "write"}],
    )
    add(
        "read-mixed-case-administrator",
        ldap=_directory(),
        requests=[{"raw": _read(target={"sam": ADMIN_SAM.lower()}), "stage": "write"}],
    )
    add(
        "read-mixed-case-members",
        ldap=_directory(),
        requests=[
            {
                "raw": _read(
                    "member-add",
                    target={"group_sam": GROUP_SAM, "member_sam": MEMBER_SAM},
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "read-a-name-that-differs-by-more-than-the-case",
        ldap=_directory(),
        requests=[{"raw": _read(target={"sam": "seed-asre"}), "stage": "write"}],
    )

    # the apply mode
    add("apply-ok", ldap=_directory(), requests=[{"raw": _apply(), "stage": "write"}])
    add(
        "apply-mixed-case-account",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "disable",
                    target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
                    before={"uac": 4260352},
                    after={"uac": 4260354},
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-mixed-case-members",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "member-add",
                    target={
                        "group_guid": GROUP_GUID,
                        "group_sid": GROUP_SID,
                        "group_sam": GROUP_SAM,
                        "member_guid": MEMBER_GUID,
                        "member_sid": MEMBER_SID,
                        "member_sam": MEMBER_SAM,
                    },
                    before={"member": "absent"},
                    after={"member": "present"},
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-a-name-that-differs-by-more-than-the-case",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    target={
                        "guid": SEED_GUID,
                        "sid": SEED_SID,
                        "sam": "seed-asre",
                        "bit": 4194304,
                    }
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-bad-token",
        ldap=_directory(),
        requests=[{"raw": _apply(token="f" * 64), "stage": "write"}],
    )
    add(
        "apply-expired",
        ldap=_directory(),
        requests=[{"raw": _apply(nbf=1700000000, exp=1700000600), "stage": "write"}],
    )
    add(
        "apply-replay",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _apply(), "stage": "write"},
        ],
    )
    add(
        "apply-replay-numbered-record",
        ldap=_directory(),
        store_files={TXID + ".0.json": _stored_record("refused")},
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-replay-legacy-record",
        ldap=_directory(),
        store_files={TXID + ".json": _stored_record("refused")},
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-record-create-collision",
        ldap=_directory(),
        record_collision=TXID,
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-not-found",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    target={
                        "guid": "9999619f-8b86-d011-b42d-00c04fc964ff",
                        "sid": SEED_SID,
                        "sam": SEED_SAM,
                        "bit": 4194304,
                    }
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-conflict-before",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=512,
                    parent=OU_USERS,
                )
            ]
        ),
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-conflict-write",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                    modify_error=16,
                )
            ]
        ),
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-denied-outside-the-delegation",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                    delegated=False,
                )
            ]
        ),
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-error",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                    modify_error=1,
                )
            ]
        ),
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-error-after-the-write-landed",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                    modify_error_after_write=1,
                )
            ]
        ),
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-error-after-the-write-landed-and-no-reread",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                    modify_error_after_write=1,
                )
            ],
            search_errors_after_write=1,
        ),
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-not-pdc",
        ldap=_directory(pdc=False),
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-risk-mismatch",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    admin_count=1,
                    parent=OU_USERS,
                )
            ]
        ),
        requests=[{"raw": _apply(risk="MED"), "stage": "write"}],
    )
    add(
        "apply-risk-mismatch-high",
        ldap=_directory(),
        requests=[{"raw": _apply(risk="HIGH"), "stage": "write"}],
    )
    # BUILTIN Administrators: the fake holds it in every directory, as the
    # lab DC measured it (SID S-1-5-32-544, outside the domain)
    add(
        "read-builtin-privileged-group",
        ldap=_directory(),
        requests=[
            {
                "raw": _read(
                    "member-add",
                    target={"group_sam": "administrators", "member_sam": MEMBER_SAM},
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-builtin-privileged-group",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "member-add",
                    target={
                        "group_guid": BUILTIN_ADMINS_GUID,
                        "group_sid": "S-1-5-32-544",
                        "group_sam": "administrators",
                        "member_guid": MEMBER_GUID,
                        "member_sid": MEMBER_SID,
                        "member_sam": MEMBER_SAM,
                    },
                    before={"member": "absent"},
                    after={"member": "present"},
                    risk="HIGH",
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-privileged-target",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "member-add",
                    target={
                        "group_guid": ADMINS_GUID,
                        "group_sid": ADMINS_SID,
                        "group_sam": "domain-admins",
                        "member_guid": MEMBER_GUID,
                        "member_sid": MEMBER_SID,
                        "member_sam": MEMBER_SAM,
                    },
                    before={"member": "absent"},
                    after={"member": "present"},
                    risk="HIGH",
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-privileged-write-account",
        ldap=_directory(
            objects=[
                _object(
                    f"CN=newton-ops,{OU_OPS}",
                    OPS_GUID,
                    OPS_SID,
                    "newton-ops",
                    token_groups=["S-1-5-21-1-2-3-513", ADMINS_SID],
                ),
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                ),
            ]
        ),
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-write-account-target",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "disable",
                    target={"guid": OPS_GUID, "sid": OPS_SID, "sam": "newton-ops"},
                    before={"uac": 512},
                    after={"uac": 514},
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-write-account-member",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "member-add",
                    target={
                        "group_guid": GROUP_GUID,
                        "group_sid": GROUP_SID,
                        "group_sam": GROUP_SAM,
                        "member_guid": OPS_GUID,
                        "member_sid": OPS_SID,
                        "member_sam": "newton-ops",
                    },
                    before={"member": "absent"},
                    after={"member": "present"},
                ),
                "stage": "write",
            }
        ],
    )
    for name, sam, sid, uac in (
        ("apply-rid-502-target", SEED_SAM, "S-1-5-21-1-2-3-502", 512),
        ("apply-krbtgt-target", "krbtgt", SEED_SID, 512),
        ("apply-rodc-krbtgt-target", "krbtgt_1000", SEED_SID, 512),
        ("apply-trust-account-target", SEED_SAM, SEED_SID, 512 | 0x800),
    ):
        add(
            name,
            ldap=_directory(
                objects=[
                    _object(
                        f"CN={sam},{OU_USERS}",
                        SEED_GUID,
                        sid,
                        sam,
                        uac=uac,
                        parent=OU_USERS,
                    )
                ]
            ),
            requests=[
                {
                    "raw": _apply(
                        "disable",
                        target={"guid": SEED_GUID, "sid": sid, "sam": sam},
                        before={"uac": uac},
                        after={"uac": uac | 2},
                    ),
                    "stage": "write",
                }
            ],
        )
    for name, ldap in (
        ("apply-missing-write-account", _directory(omit_write_account=True)),
        (
            "apply-empty-write-account-tokengroups",
            _directory(write_token_groups=[]),
        ),
        (
            "apply-undecodable-write-account-tokengroups",
            _directory(write_token_groups=["not-a-sid"]),
        ),
    ):
        add(name, ldap=ldap, requests=[{"raw": _apply(), "stage": "write"}])
    add(
        "apply-denied-dc-account",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352 | 0x2000,
                    parent=OU_USERS,
                )
            ]
        ),
        requests=[
            {
                "raw": _apply(
                    "disable",
                    target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
                    before={"uac": 4260352 | 0x2000},
                    after={"uac": 4260352 | 0x2000 | 2},
                    risk="HIGH",
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-denied-verb-rule",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "disable",
                    target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
                    before={"uac": 4260352},
                    after={"uac": 4260352},
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-unlock",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    lockout=1000,
                    parent=OU_USERS,
                )
            ]
        ),
        requests=[
            {
                "raw": _apply(
                    "unlock",
                    target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
                    before={"lockout": 1000},
                    after={"lockout": 0},
                    window=120,
                    risk="LOW",
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-user-create",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "user-create",
                    target={"parent_guid": PARENT_GUID, "sam": "new.user"},
                    before={"object": "absent"},
                    after={"object": "present"},
                    secret="a-very-secret-password",
                ),
                "stage": "write",
            }
        ],
    )
    for name, ldap in (
        ("apply-user-create-missing-guid", _directory(created_missing_guid=True)),
        ("apply-user-create-missing-usn", _directory(created_missing_usn=True)),
        (
            "apply-user-create-missing-facts-delete-fails",
            _directory(created_missing_guid=True, ldap_delete_error=1),
        ),
    ):
        add(
            name,
            ldap=ldap,
            requests=[
                {
                    "raw": _apply(
                        "user-create",
                        target={"parent_guid": PARENT_GUID, "sam": "new.user"},
                        before={"object": "absent"},
                        after={"object": "present"},
                        secret="a-very-secret-password",
                    ),
                    "stage": "write",
                }
            ],
        )
    add(
        "apply-user-create-then-abort",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "user-create",
                    target={"parent_guid": PARENT_GUID, "sam": "new.user"},
                    before={"object": "absent"},
                    after={"object": "present"},
                    secret="a-very-secret-password",
                ),
                "stage": "write",
            },
            {"raw": _mode("abort"), "stage": "write"},
        ],
    )
    add(
        # The undo facts of the new user are written in a new generation
        # of the store, and another writer takes that file first: the
        # facts cannot be recorded.
        "apply-user-create-record-write-error",
        ldap=_directory(),
        record_is_directory_file=TXID + ".1.json",
        requests=[
            {
                "raw": _apply(
                    "user-create",
                    target={"parent_guid": PARENT_GUID, "sam": "new.user"},
                    before={"object": "absent"},
                    after={"object": "present"},
                    secret="a-very-secret-password",
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-user-create-then-abort-with-a-member",
        ldap=_directory(created_member=f"CN={MEMBER_SAM},{OU_USERS}"),
        requests=[
            {
                "raw": _apply(
                    "user-create",
                    target={"parent_guid": PARENT_GUID, "sam": "new.user"},
                    before={"object": "absent"},
                    after={"object": "present"},
                    secret="a-very-secret-password",
                ),
                "stage": "write",
            },
            {"raw": _mode("abort"), "stage": "write"},
        ],
    )
    add(
        "apply-schema",
        ldap=_directory(),
        requests=[{"raw": "{not json", "stage": "write"}],
    )
    add(
        "apply-wrong-device",
        ldap=_directory(),
        requests=[{"raw": _apply(device="other-domain"), "stage": "write"}],
    )
    add(
        "apply-unavailable",
        ldap=_directory(),
        hold_lock=True,
        lock_timeout=1,
        requests=[{"raw": _apply(), "stage": "write"}],
    )

    # the move verb (SPEC section 3)
    add(
        "move-ok",
        ldap=_directory(),
        requests=[{"raw": _move(), "stage": "write"}],
    )
    add(
        "move-conflict",
        ldap=_directory(),
        requests=[{"raw": _move(before_parent=OTHER_PARENT_GUID), "stage": "write"}],
    )
    add(
        "move-then-abort",
        ldap=_directory(),
        requests=[
            {"raw": _move(), "stage": "write"},
            {"raw": _mode("abort"), "stage": "write"},
        ],
    )
    add(
        "move-undo-conflict",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                    move_drift_to=f"CN={SEED_SAM},OU=Elsewhere,{DOMAIN_DN}",
                ),
                _object(
                    OU_USERS,
                    OU_GUID,
                    None,
                    None,
                    object_class=["top", "organizationalUnit"],
                ),
                _object(
                    OU_OPS,
                    OU_OPS_GUID,
                    None,
                    None,
                    object_class=["top", "organizationalUnit"],
                ),
            ]
        ),
        requests=[
            {"raw": _move(), "stage": "write"},
            {"raw": _mode("abort"), "stage": "write"},
        ],
    )
    add(
        "move-into-the-domain-controllers-ou",
        ldap=_directory(),
        requests=[{"raw": _move(after_parent=DC_OU_GUID), "stage": "write"}],
    )
    add(
        "move-not-a-container",
        ldap=_directory(),
        requests=[{"raw": _move(after_parent=SEED_GUID), "stage": "write"}],
    )

    # the quota of the domain head
    add(
        "maq-ok",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "maq",
                    target={"guid": PARENT_GUID},
                    before={"maq": 10},
                    after={"maq": 20},
                ),
                "stage": "write",
            }
        ],
    )

    # the rules of a domain controller account
    add(
        "apply-denied-dc-account-trust-bit",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=0x2000 | 0x80000,
                    parent=OU_USERS,
                )
            ]
        ),
        requests=[
            {
                "raw": _apply(
                    "uac-clear",
                    target={
                        "guid": SEED_GUID,
                        "sid": SEED_SID,
                        "sam": SEED_SAM,
                        "bit": 524288,
                    },
                    before={"uac": 0x2000 | 0x80000},
                    after={"uac": 0x2000},
                    risk="HIGH",
                ),
                "stage": "write",
            }
        ],
    )

    # the user principal name of a new user
    add(
        "apply-user-create-upn-exists",
        ldap=_directory(
            objects=[
                _object(
                    f"CN=other,{OU_USERS}",
                    MEMBER_GUID,
                    MEMBER_SID,
                    MEMBER_SAM,
                    upn="new.user@" + DNS_DOMAIN,
                    parent=OU_USERS,
                )
            ]
        ),
        requests=[
            {
                "raw": _apply(
                    "user-create",
                    target={"parent_guid": PARENT_GUID, "sam": "new.user"},
                    before={"object": "absent"},
                    after={"object": "present"},
                    secret="a-very-secret-password",
                ),
                "stage": "write",
            }
        ],
    )

    # the read of a user-create checks the user principal name too
    add(
        "read-user-create-upn-exists",
        ldap=_directory(
            objects=[
                _object(
                    f"CN=other,{OU_USERS}",
                    MEMBER_GUID,
                    MEMBER_SID,
                    MEMBER_SAM,
                    upn="new.user@" + DNS_DOMAIN,
                    parent=OU_USERS,
                )
            ]
        ),
        requests=[
            {
                "raw": _read("user-create", {"parent_guid": PARENT_GUID, "sam": "new.user"}),
                "stage": "write",
            }
        ],
    )
    add(
        "read-user-create-upn-free",
        ldap=_directory(),
        requests=[
            {
                "raw": _read("user-create", {"parent_guid": PARENT_GUID, "sam": "new.user"}),
                "stage": "write",
            }
        ],
    )
    # a domain DN the DNS name cannot be derived from
    add(
        "read-user-create-no-dns-name",
        ldap=_directory(domain_dn=ODD_DOMAIN_DN),
        requests=[
            {
                "raw": _read("user-create", {"parent_guid": PARENT_GUID, "sam": "new.user"}),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-user-create-no-dns-name",
        ldap=_directory(domain_dn=ODD_DOMAIN_DN),
        requests=[
            {
                "raw": _apply(
                    "user-create",
                    target={"parent_guid": PARENT_GUID, "sam": "new.user"},
                    before={"object": "absent"},
                    after={"object": "present"},
                    secret="a-very-secret-password",
                ),
                "stage": "write",
            }
        ],
    )

    # the order of the checks
    add(
        "apply-bad-token-before-the-verb-rules",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "disable",
                    target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
                    before={"uac": 4260352},
                    after={"uac": 4260352},
                    token="f" * 64,
                ),
                "stage": "write",
            }
        ],
    )

    # a store that fails is not a replay
    add(
        "apply-record-store-error",
        ldap=_directory(),
        record_is_directory=TXID,
        requests=[{"raw": _apply(), "stage": "write"}],
    )

    # an adapter that leaks the index of its collections
    # makes the answer of the mode a list.  The entry point must answer one
    # object (an error) and name the leaked types on stderr.
    add(
        "apply-with-a-leaking-adapter",
        ldap=_directory(leak_indexes=True),
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "user-create-with-a-leaking-adapter",
        ldap=_directory(leak_indexes=True),
        requests=[
            {
                "raw": _apply(
                    "user-create",
                    target={"parent_guid": PARENT_GUID, "sam": "new.user"},
                    before={"object": "absent"},
                    after={"object": "present"},
                    secret="a-very-secret-password",
                ),
                "stage": "write",
            }
        ],
    )

    # numbered records are append-only.  A legacy record is
    # generation zero, the highest numbered record is current, and a stale
    # temporary file is not a record.
    add(
        "status-legacy-record",
        ldap=_directory(),
        store_files={TXID + ".json": _stored_record("confirmed")},
        requests=[{"raw": _mode("status"), "stage": "write"}],
    )
    add(
        "status-highest-numbered-record",
        ldap=_directory(),
        store_files={
            TXID + ".0.json": _stored_record("armed", undo_at=NOW - 1),
            TXID + ".1.json": _stored_record("confirmed"),
        },
        requests=[{"raw": _mode("status"), "stage": "write"}],
    )
    add(
        "status-ignores-leftover-new-file",
        ldap=_directory(),
        store_files={
            TXID + ".0.json": _stored_record("confirmed"),
            TXID + ".9.json.new": _stored_record("armed", undo_at=NOW - 1),
        },
        requests=[{"raw": _mode("status"), "stage": "write"}],
    )
    add(
        "read-lock-unauthorized",
        ldap=_directory(),
        lock_unauthorized=True,
        requests=[{"raw": _read(), "stage": "write"}],
    )
    add(
        "undo-lock-unauthorized",
        ldap=_directory(),
        lock_unauthorized=True,
        requests=[{"stage": "undo", "undo": TXID}],
    )

    # the privilege walk fails closed
    add(
        "apply-privileged-deep-group",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={GROUP_SAM},{OU_USERS}",
                    GROUP_GUID,
                    GROUP_SID,
                    GROUP_SAM,
                    object_class=["top", "group"],
                    member_of=[f"CN=deep-0,{OU_USERS}"],
                    parent=OU_USERS,
                ),
                _object(
                    f"CN={MEMBER_SAM},{OU_USERS}",
                    MEMBER_GUID,
                    MEMBER_SID,
                    MEMBER_SAM,
                    parent=OU_USERS,
                ),
            ]
            + _deep_groups(40)
        ),
        requests=[
            {
                "raw": _apply(
                    "member-add",
                    target={
                        "group_guid": GROUP_GUID,
                        "group_sid": GROUP_SID,
                        "group_sam": GROUP_SAM,
                        "member_guid": MEMBER_GUID,
                        "member_sid": MEMBER_SID,
                        "member_sam": MEMBER_SAM,
                    },
                    before={"member": "absent"},
                    after={"member": "present"},
                    risk="HIGH",
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "apply-privileged-unreadable-group",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={GROUP_SAM},{OU_USERS}",
                    GROUP_GUID,
                    GROUP_SID,
                    GROUP_SAM,
                    object_class=["top", "group"],
                    member_of=[f"CN=ghost,{OU_USERS}"],
                    parent=OU_USERS,
                ),
                _object(
                    f"CN={MEMBER_SAM},{OU_USERS}",
                    MEMBER_GUID,
                    MEMBER_SID,
                    MEMBER_SAM,
                    parent=OU_USERS,
                ),
            ]
        ),
        requests=[
            {
                "raw": _apply(
                    "member-add",
                    target={
                        "group_guid": GROUP_GUID,
                        "group_sid": GROUP_SID,
                        "group_sam": GROUP_SAM,
                        "member_guid": MEMBER_GUID,
                        "member_sid": MEMBER_SID,
                        "member_sam": MEMBER_SAM,
                    },
                    before={"member": "absent"},
                    after={"member": "present"},
                    risk="HIGH",
                ),
                "stage": "write",
            }
        ],
    )

    # the membership of a group
    add(
        "member-add-ok",
        ldap=_directory(),
        requests=[
            {
                "raw": _apply(
                    "member-add",
                    target={
                        "group_guid": GROUP_GUID,
                        "group_sid": GROUP_SID,
                        "group_sam": GROUP_SAM,
                        "member_guid": MEMBER_GUID,
                        "member_sid": MEMBER_SID,
                        "member_sam": MEMBER_SAM,
                    },
                    before={"member": "absent"},
                    after={"member": "present"},
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "member-remove-ok",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={GROUP_SAM},{OU_USERS}",
                    GROUP_GUID,
                    GROUP_SID,
                    GROUP_SAM,
                    object_class=["top", "group"],
                    member=[f"CN={MEMBER_SAM},{OU_USERS}"],
                    parent=OU_USERS,
                ),
                _object(
                    f"CN={MEMBER_SAM},{OU_USERS}",
                    MEMBER_GUID,
                    MEMBER_SID,
                    MEMBER_SAM,
                    parent=OU_USERS,
                ),
            ]
        ),
        requests=[
            {
                "raw": _apply(
                    "member-remove",
                    target={
                        "group_guid": GROUP_GUID,
                        "group_sid": GROUP_SID,
                        "group_sam": GROUP_SAM,
                        "member_guid": MEMBER_GUID,
                        "member_sid": MEMBER_SID,
                        "member_sam": MEMBER_SAM,
                    },
                    before={"member": "present"},
                    after={"member": "absent"},
                ),
                "stage": "write",
            }
        ],
    )

    # the confirm mode
    add(
        "confirm-ok",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
        ],
    )
    add(
        "confirm-conflict",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                    drift_after_write=999999,
                )
            ]
        ),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
        ],
    )
    add(
        "confirm-not-found",
        ldap=_directory(),
        requests=[{"raw": _mode("confirm"), "stage": "write"}],
    )
    add(
        "confirm-after-abort",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("abort"), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
        ],
    )
    add(
        "confirm-twice",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
        ],
    )
    # An unlock is confirmed at the apply (no undo is armed): the confirm
    # CORE sends after every DC shows the after-image answers ok.
    unlock_raw = _apply(
        "unlock",
        target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
        before={"lockout": 1000},
        after={"lockout": 0},
        window=120,
        risk="LOW",
    )
    for name, drift in (("confirm-unlock", None), ("confirm-unlock-changed", 7)):
        locked = _object(
            f"CN={SEED_SAM},{OU_USERS}",
            SEED_GUID,
            SEED_SID,
            SEED_SAM,
            uac=512,
            lockout=1000,
            parent=OU_USERS,
        )
        if drift is not None:
            locked["drift_after_write"] = drift
        add(
            name,
            ldap=_directory(objects=[locked]),
            requests=[
                {"raw": unlock_raw, "stage": "write"},
                {"raw": _mode("confirm"), "stage": "write"},
            ],
        )
    # A confirmed record of a verb that arms an undo is never confirmed
    # again, even when the target shows the after-image.
    add(
        "confirm-confirmed-uac-clear",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=66048,
                    parent=OU_USERS,
                )
            ]
        ),
        store_files={TXID + ".0.json": _stored_record("confirmed")},
        requests=[{"raw": _mode("confirm"), "stage": "write"}],
    )
    add(
        "confirm-task-delete-error",
        ldap=_directory(),
        scheduler_delete_error=True,
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
            {"raw": _mode("status"), "stage": "write"},
        ],
    )
    add(
        "confirm-task-delete-error-then-undo",
        ldap=_directory(),
        scheduler_delete_error=True,
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
            {"stage": "undo", "undo": TXID},
        ],
    )
    add(
        # The confirmation is written in a new generation of the store,
        # and another writer takes that file first: the confirmation
        # cannot be recorded.
        "confirm-record-write-error",
        ldap=_directory(),
        record_is_directory_file=TXID + ".1.json",
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
            {"raw": _mode("status"), "stage": "write"},
        ],
    )

    # the abort mode
    add(
        "abort-ok",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("abort"), "stage": "write"},
        ],
    )
    add(
        "abort-conflict",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    parent=OU_USERS,
                    drift_after_write=999999,
                )
            ]
        ),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("abort"), "stage": "write"},
        ],
    )
    add(
        "abort-not-found",
        ldap=_directory(),
        requests=[{"raw": _mode("abort"), "stage": "write"}],
    )
    add(
        "abort-after-confirm",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
            {"raw": _mode("abort"), "stage": "write"},
        ],
    )
    add(
        "abort-after-refusal",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=512,
                    parent=OU_USERS,
                )
            ]
        ),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("abort"), "stage": "write"},
        ],
    )

    # the status mode
    add(
        "status-armed",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("status"), "stage": "write"},
        ],
    )
    add(
        "status-confirmed",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
            {"raw": _mode("status"), "stage": "write"},
        ],
    )
    add(
        "status-not-found",
        ldap=_directory(),
        requests=[{"raw": _mode("status"), "stage": "write"}],
    )

    # the undo
    add(
        "undo-ok",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"stage": "undo", "undo": TXID},
        ],
    )
    add(
        "undo-with-ssh-connection",
        ldap=_directory(),
        ssh_connection="10.0.0.1 5000 10.0.0.2 5000",
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"stage": "undo", "undo": TXID},
        ],
    )
    add(
        "undo-with-ssh-client",
        ldap=_directory(),
        ssh_client="10.0.0.1 5000 22",
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"stage": "undo", "undo": TXID},
        ],
    )
    add(
        "undo-not-found",
        ldap=_directory(),
        requests=[{"stage": "undo", "undo": TXID}],
    )
    add(
        "undo-bad-txid",
        ldap=_directory(),
        requests=[{"stage": "undo", "undo": "../../etc/passwd"}],
    )
    add(
        "undo-after-confirm",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"raw": _mode("confirm"), "stage": "write"},
            {"stage": "undo", "undo": TXID},
        ],
    )
    add(
        "undo-after-refusal",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=512,
                    parent=OU_USERS,
                )
            ]
        ),
        requests=[
            {"raw": _apply(), "stage": "write"},
            {"stage": "undo", "undo": TXID},
        ],
    )

    # exceptions after record creation have a final recorded outcome
    add(
        "apply-register-error-before-write",
        ldap=_directory(),
        scheduler_register_error=True,
        requests=[{"raw": _apply(), "stage": "write"}],
    )
    add(
        "apply-readback-error-after-write",
        ldap=_directory(search_errors_after_write=1),
        requests=[{"raw": _apply(), "stage": "write"}],
    )

    # the sweep: the deadline of an armed record has passed
    add(
        "sweep-undoes-the-armed-record",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write", "now": NOW},
            {"raw": _mode("status"), "stage": "write", "now": NOW + 900},
        ],
    )
    add(
        "sweep-leaves-a-record-alone-until-its-deadline",
        ldap=_directory(),
        requests=[
            {"raw": _apply(), "stage": "write", "now": NOW},
            {"raw": _mode("status"), "stage": "write", "now": NOW + 100},
        ],
    )

    # the privileged groups
    add(
        "nested-privileged-group",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    member_of=[NESTED_DN],
                    parent=OU_USERS,
                ),
                _object(
                    NESTED_DN,
                    NESTED_GUID,
                    NESTED_SID,
                    "nested-admins",
                    object_class=["top", "group"],
                    member_of=[ADMINS_DN],
                    parent=OU_USERS,
                ),
                _object(
                    ADMINS_DN,
                    ADMINS_GUID,
                    ADMINS_SID,
                    "domain-admins",
                    object_class=["top", "group"],
                    parent=DOMAIN_DN,
                ),
            ]
        ),
        requests=[
            {
                "raw": _apply(
                    "disable",
                    target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
                    before={"uac": 4260352},
                    after={"uac": 4260354},
                    risk="HIGH",
                ),
                "stage": "write",
            }
        ],
    )
    add(
        "memberof-cycle",
        ldap=_directory(
            objects=[
                _object(
                    f"CN={SEED_SAM},{OU_USERS}",
                    SEED_GUID,
                    SEED_SID,
                    SEED_SAM,
                    uac=4260352,
                    member_of=[CYCLE_DN],
                    parent=OU_USERS,
                ),
                _object(
                    CYCLE_DN,
                    CYCLE_GUID,
                    CYCLE_SID,
                    "cycle-one",
                    object_class=["top", "group"],
                    member_of=[CYCLE_DN_TWO],
                    parent=OU_USERS,
                ),
                _object(
                    CYCLE_DN_TWO,
                    "f19619ff-8b86-d011-b42d-00c04fc964ff",
                    "S-1-5-21-1-2-3-1112",
                    "cycle-two",
                    object_class=["top", "group"],
                    member_of=[CYCLE_DN],
                    parent=OU_USERS,
                ),
            ]
        ),
        requests=[{"raw": _apply(), "stage": "write"}],
    )

    return cases


def _pwsh() -> str:
    """The shell of the tests, or a skip."""
    if not PWSH.is_file():
        pytest.skip(
            f"PowerShell 7.4 is not installed at {PWSH}: the Windows write "
            "helper cannot be exercised"
        )
    return str(PWSH)


@pytest.fixture(scope="module")
def answers(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    """The answers of the harness to every case."""
    _pwsh()
    cases = _cases()
    directory = tmp_path_factory.mktemp("win-write-modes")
    cases_path = directory / "cases.json"
    cases_path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    finished = subprocess.run(
        [
            _pwsh(),
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


def _codes(answer: dict[str, Any]) -> list[str]:
    """The code of every request of a case."""
    return [str(result["code"]) for result in answer["results"]]


def _calls(answer: dict[str, Any]) -> list[str]:
    """The call log of a case."""
    return [str(entry) for entry in answer["calls"]]


def _current_record(answer: dict[str, Any]) -> dict[str, Any]:
    """The highest numbered record, with a legacy record as generation zero."""
    candidates: list[tuple[int, bool, str]] = []
    for name in answer["files"]:
        if name == TXID + ".json":
            candidates.append((0, False, name))
            continue
        prefix = TXID + "."
        suffix = ".json"
        if name.startswith(prefix) and name.endswith(suffix):
            generation = name[len(prefix) : -len(suffix)]
            if generation.isdigit():
                candidates.append((int(generation), True, name))
    if not candidates:
        raise AssertionError("the transaction has no record")
    name = max(candidates)[2]
    return json.loads(answer["files"][name])


def _object_of(answer: dict[str, Any], sam: str) -> dict[str, Any]:
    """The object of the fake directory with that name."""
    wanted = sam.lower()
    for entry in answer["objects"]:
        if str(entry["sam"]).lower() == wanted:
            return entry
    raise AssertionError(f"the object {sam} is not in the directory")


def _object_with_dn(answer: dict[str, Any], dn: str) -> dict[str, Any]:
    """The object of the fake directory with that distinguished name."""
    for entry in answer["objects"]:
        if str(entry["dn"]) == dn:
            return entry
    raise AssertionError(f"the object {dn} is not in the directory")


def test_the_read_mode_answers_the_live_values_and_the_facts(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A read answers the live values, the ids and the facts."""
    answer = answers["read-ok"]
    assert answer["code"] == "ok"
    response = answer["response"]
    assert response["live"] == {"uac": 4260352}
    assert response["ids"]["guid"] == SEED_GUID
    assert response["ids"]["sid"] == SEED_SID
    assert response["ids"]["sam"] == SEED_SAM
    facts = response["facts"]["target"]
    assert facts["admin_count"] == 0
    assert facts["dc_account"] is False
    assert facts["privileged"] is False
    assert facts["pdc"] is True
    assert "user" in facts["object_class"]


def test_the_read_mode_refuses_an_object_that_is_not_there(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A read of an object that is not there is not_found."""
    assert answers["read-not-found"]["code"] == "not_found"


def test_the_read_mode_refuses_two_objects_with_the_same_name(
    answers: dict[str, dict[str, Any]],
) -> None:
    """Two objects with one name are not_found."""
    assert answers["read-two-matches"]["code"] == "not_found"


def test_the_apply_mode_writes_and_arms_the_undo(
    answers: dict[str, dict[str, Any]],
) -> None:
    """An apply writes the after-image and arms the undo first."""
    answer = answers["apply-ok"]
    assert answer["code"] == "ok"
    response = answer["response"]
    assert response["live"] == {"uac": 66048}
    assert response["undo_at"] == NOW + 600
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]
    calls = _calls(answer)
    assert "task:register newton-undo-" + TXID in calls
    assert "ldap:modify userAccountControl" in calls
    assert answer["tasks"] == [
        {"name": "newton-undo-" + TXID, "boundary": "2027-01-15T08:10:00Z"}
    ]


def test_the_apply_mode_arms_the_undo_before_it_writes(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The undo is armed before the write: the call log proves the order."""
    calls = _calls(answers["apply-ok"])
    register = calls.index("task:register newton-undo-" + TXID)
    modify = calls.index("ldap:modify userAccountControl")
    assert register < modify


def test_the_apply_mode_refuses_a_bad_token(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A request the owner did not sign is refused, and nothing is written."""
    answer = answers["apply-bad-token"]
    assert answer["code"] == "bad_token"
    assert "ldap:modify userAccountControl" not in _calls(answer)
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


def test_the_apply_mode_refuses_an_expired_approval(
    answers: dict[str, dict[str, Any]],
) -> None:
    """An approval that is over is refused."""
    answer = answers["apply-expired"]
    assert answer["code"] == "expired"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_the_apply_mode_refuses_a_replay(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The same transaction id twice is a replay."""
    answer = answers["apply-replay"]
    assert _codes(answer) == ["ok", "replay"]
    assert _calls(answer).count("ldap:modify userAccountControl") == 1


@pytest.mark.parametrize(
    "name", ["apply-replay-numbered-record", "apply-replay-legacy-record"]
)
def test_any_record_file_makes_an_apply_a_replay(
    answers: dict[str, dict[str, Any]], name: str
) -> None:
    """Legacy and numbered records both reserve the txid."""
    answer = answers[name]
    assert answer["code"] == "replay"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_state_changes_append_numbered_records(
    answers: dict[str, dict[str, Any]],
) -> None:
    """Confirming appends and leaves the armed record intact."""
    files = answers["confirm-ok"]["files"]
    first = json.loads(files[TXID + ".0.json"])
    second = json.loads(files[TXID + ".1.json"])
    assert first["state"] == "armed"
    assert second["state"] == "confirmed"
    assert TXID + ".json" not in files
    assert TXID + ".json.new" not in files


def test_a_create_new_collision_is_an_error_and_writes_nothing(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A writer inside the lock cannot be mistaken for replay."""
    answer = answers["apply-record-create-collision"]
    assert answer["code"] == "error"
    assert "ldap:modify userAccountControl" not in _calls(answer)
    assert answer["files"] == {TXID + ".0.json": '{"writer":"other"}'}


@pytest.mark.parametrize(
    ("name", "state"),
    [
        ("status-legacy-record", "confirmed"),
        ("status-highest-numbered-record", "confirmed"),
        ("status-ignores-leftover-new-file", "confirmed"),
    ],
)
def test_current_record_is_the_highest_generation(
    answers: dict[str, dict[str, Any]], name: str, state: str
) -> None:
    """Legacy is zero, numbered wins, and *.new is ignored."""
    answer = answers[name]
    assert answer["code"] == "ok"
    assert answer["response"]["state"] == state
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_an_unauthorized_lock_is_unavailable_and_reports_only_on_stderr(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The measured ACL refusal is visible but not JSON output."""
    answer = answers["read-lock-unauthorized"]
    assert answer["code"] == "unavailable"
    assert "measured tx ACL denies this open" in answer["results"][0]["stderr"]
    assert "measured tx ACL denies this open" not in json.dumps(answer["response"])


def test_the_undo_task_uses_the_same_read_only_lock_refusal(
    answers: dict[str, dict[str, Any]],
) -> None:
    """S4U undo enters through the same measured-ACL lock path."""
    result = answers["undo-lock-unauthorized"]["results"][0]
    assert result["code"] == "unavailable"
    assert "measured tx ACL denies this open" in result["stderr"]


def test_the_apply_mode_refuses_a_target_that_is_not_there(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A target that is not there is not_found, and the record says so."""
    answer = answers["apply-not-found"]
    assert answer["code"] == "not_found"
    record = _current_record(answer)
    assert record["state"] == "refused"


def test_the_apply_mode_refuses_a_before_image_that_does_not_match(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A live value that is not the before-image is a conflict."""
    answer = answers["apply-conflict-before"]
    assert answer["code"] == "conflict"
    assert answer["response"]["live"] == {"uac": 512}
    assert "ldap:modify userAccountControl" not in _calls(answer)
    record = _current_record(answer)
    assert record["state"] == "refused"


def test_the_apply_mode_refuses_a_write_that_found_no_old_value(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A write that answers 16 is a conflict, and the undo is disarmed."""
    answer = answers["apply-conflict-write"]
    assert answer["code"] == "conflict"
    assert "task:delete newton-undo-" + TXID in _calls(answer)
    record = _current_record(answer)
    assert record["state"] == "refused"


def test_the_apply_mode_refuses_a_write_outside_the_delegation(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A write that answers 50 is denied."""
    answer = answers["apply-denied-outside-the-delegation"]
    assert answer["code"] == "denied"
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


def test_the_apply_mode_answers_an_unexpected_error(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A write that answers anything else is an error."""
    assert answers["apply-error"]["code"] == "error"


def test_an_error_of_a_write_that_never_landed_is_refused_and_disarmed(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The write failed and the target still shows the before-image.

    SPEC-1.4-REQUEST section 6: a failure other than a conflict runs the
    undo at once.  Nothing was written, so there is nothing to put back:
    the record is refused and the undo task is gone.
    """
    answer = answers["apply-error"]
    assert answer["code"] == "error"
    assert _current_record(answer)["state"] == "refused"
    assert "task:delete newton-undo-" + TXID in _calls(answer)
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


def test_an_error_of_a_write_that_landed_runs_the_undo_at_once(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The server applied the modify and the answer was lost.

    The helper re-reads the target, finds the after-image and runs the
    undo at once, as the Samba helper does: the change never stays on
    the DC with no undo armed.
    """
    answer = answers["apply-error-after-the-write-landed"]
    assert answer["code"] == "error"
    record = _current_record(answer)
    assert record["state"] == "undone"
    assert record["restored"] is True
    assert "task:delete newton-undo-" + TXID in _calls(answer)
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


def test_an_error_of_a_write_that_cannot_be_re_read_stays_armed(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The write landed and the re-read of the target failed too.

    The helper cannot tell whether the write landed, so it leaves the
    record armed and the undo task registered: the task puts the value
    back at undo_at.
    """
    answer = answers["apply-error-after-the-write-landed-and-no-reread"]
    assert answer["code"] == "error"
    assert _current_record(answer)["state"] == "armed"
    assert "task:delete newton-undo-" + TXID not in _calls(answer)


def test_the_apply_mode_runs_only_on_the_pdc(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A DC that does not hold the PDC emulator role refuses the apply."""
    answer = answers["apply-not-pdc"]
    assert answer["code"] == "not_pdc"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_the_apply_mode_re_derives_the_risk(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The helper computes the risk itself and refuses a wrong one."""
    assert answers["apply-risk-mismatch"]["code"] == "risk_mismatch"
    assert answers["apply-risk-mismatch-high"]["code"] == "risk_mismatch"
    answer = answers["apply-risk-mismatch"]
    assert "ldap:modify userAccountControl" not in _calls(answer)
    record = _current_record(answer)
    assert record["state"] == "refused"


def test_the_apply_mode_refuses_a_privileged_group(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A membership of a privileged group is refused."""
    answer = answers["apply-privileged-target"]
    assert answer["code"] == "privileged"
    assert "ldap:modify member" not in _calls(answer)


def test_the_read_mode_names_a_builtin_group_privileged(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A member-add read of BUILTIN Administrators.

    The read answers ok with the group's SID S-1-5-32-544 and privileged
    true (the helper's BUILTIN list, not the RID table): that is what the
    plan reads before it refuses the change as privileged.
    """
    answer = answers["read-builtin-privileged-group"]
    assert answer["code"] == "ok"
    response = answer["response"]
    assert response["ids"]["group_sid"] == "S-1-5-32-544"
    assert response["ids"]["group_sam"] == "administrators"
    assert response["facts"]["group"]["privileged"] is True
    assert response["facts"]["group"]["admin_count"] == 1
    assert response["facts"]["member"]["privileged"] is False
    assert response["live"] == {"member": "absent"}


def test_the_apply_mode_never_writes_a_builtin_group(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A member-add to BUILTIN Administrators is refused before any write.

    Its SID is outside the domain, so the request does not fit the contract
    (schema); the plan refuses it as privileged before it gets that far.
    """
    answer = answers["apply-builtin-privileged-group"]
    assert answer["code"] == "schema"
    assert not [call for call in _calls(answer) if call.startswith("ldap:modify")]


def test_the_apply_mode_refuses_a_privileged_write_account(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The write account itself may not be in a privileged group."""
    answer = answers["apply-privileged-write-account"]
    assert answer["code"] == "privileged"
    assert "ldap:modify userAccountControl" not in _calls(answer)


@pytest.mark.parametrize(
    "name, write_call",
    [
        ("apply-write-account-target", "ldap:modify userAccountControl"),
        ("apply-write-account-member", "ldap:modify member"),
    ],
)
def test_the_apply_mode_never_writes_the_write_account(
    answers: dict[str, dict[str, Any]], name: str, write_call: str
) -> None:
    """The resolved target and member are compared with newton-ops by SID."""
    answer = answers[name]
    assert answer["code"] == "denied"
    assert write_call not in _calls(answer)


@pytest.mark.parametrize(
    "name",
    [
        "apply-rid-502-target",
        "apply-krbtgt-target",
        "apply-rodc-krbtgt-target",
        "apply-trust-account-target",
    ],
)
def test_the_apply_mode_never_writes_krbtgt_or_a_trust_account(
    answers: dict[str, dict[str, Any]], name: str
) -> None:
    """The helper refuses the protected live identity for every write."""
    answer = answers[name]
    assert answer["code"] == "denied"
    assert "ldap:modify userAccountControl" not in _calls(answer)


@pytest.mark.parametrize(
    "name",
    [
        "apply-missing-write-account",
        "apply-empty-write-account-tokengroups",
        "apply-undecodable-write-account-tokengroups",
    ],
)
def test_the_write_account_tokengroups_fail_closed(
    answers: dict[str, dict[str, Any]], name: str
) -> None:
    """A missing, empty or undecodable tokenGroups read is privileged."""
    answer = answers[name]
    assert answer["code"] == "privileged"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_the_apply_mode_refuses_a_domain_controller_account(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A domain controller account is never disabled."""
    answer = answers["apply-denied-dc-account"]
    assert answer["code"] == "denied"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_the_apply_mode_refuses_a_request_that_breaks_the_verb(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A request that breaks the table of the contract is denied."""
    answer = answers["apply-denied-verb-rule"]
    assert answer["code"] == "denied"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_the_apply_mode_arms_no_undo_for_an_unlock(
    answers: dict[str, dict[str, Any]],
) -> None:
    """An unlock has nothing to undo: no task is registered."""
    answer = answers["apply-unlock"]
    assert answer["code"] == "ok"
    assert not [call for call in _calls(answer) if call.startswith("task:register")]
    record = _current_record(answer)
    assert record["state"] == "confirmed"


def test_the_apply_mode_creates_a_user(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A user-create adds the object, disabled, with its password."""
    answer = answers["apply-user-create"]
    assert answer["code"] == "ok"
    created = _object_of(answer, "new.user")
    assert created["values"]["useraccountcontrol"] == ["514"]
    assert created["values"]["userprincipalname"] == [
        "new.user@" + DNS_DOMAIN
    ]
    assert "unicodepwd" in created["values"]


@pytest.mark.parametrize(
    "name", ["apply-user-create-missing-guid", "apply-user-create-missing-usn"]
)
def test_user_create_without_both_undo_facts_deletes_the_new_dn(
    answers: dict[str, dict[str, Any]], name: str
) -> None:
    """No ok answer is possible without both read-back facts."""
    answer = answers[name]
    assert answer["code"] == "error"
    assert "ldap:delete CN=new.user," + DOMAIN_DN in _calls(answer)
    with pytest.raises(AssertionError):
        _object_of(answer, "new.user")
    assert _current_record(answer)["state"] == "undone"


def test_user_create_cleanup_failure_records_the_new_dn(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A failed exact-DN delete records undo_failed with that DN."""
    answer = answers["apply-user-create-missing-facts-delete-fails"]
    assert answer["code"] == "error"
    record = _current_record(answer)
    assert record["state"] == "undo_failed"
    assert "CN=new.user," + DOMAIN_DN in record["conflicts"]


def test_a_user_create_whose_facts_cannot_be_recorded_deletes_the_new_object(
    answers: dict[str, dict[str, Any]],
) -> None:
    """No ok answer is possible when the undo facts cannot be written.

    The object is deleted by the name it was added with, and the answer
    is an error: the undo of a user-create needs the two facts, and it
    can never delete an object whose facts it does not hold.
    """
    answer = answers["apply-user-create-record-write-error"]
    assert answer["code"] == "error"
    assert "ldap:delete CN=new.user," + DOMAIN_DN in _calls(answer)
    with pytest.raises(AssertionError):
        _object_of(answer, "new.user")


def test_the_secret_is_in_no_file_and_in_no_answer(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The secret of a user-create is never written down."""
    answer = answers["apply-user-create"]
    secret = "a-very-secret-password"
    for name, content in answer["files"].items():
        assert secret not in content, name
    assert secret not in json.dumps(answer["response"])
    assert secret not in json.dumps(answer["objects"])


def test_the_undo_of_a_user_create_deletes_it(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The undo of a user-create deletes the object it created."""
    answer = answers["apply-user-create-then-abort"]
    assert _codes(answer) == ["ok", "ok"]
    assert answer["results"][1]["response"]["restored"] is True
    with pytest.raises(AssertionError):
        _object_of(answer, "new.user")


def test_the_undo_of_a_user_create_keeps_an_object_with_a_member(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The undo deletes a created user only when it has no member."""
    answer = answers["apply-user-create-then-abort-with-a-member"]
    assert _codes(answer) == ["ok", "ok"]
    response = answer["results"][1]["response"]
    assert response["restored"] is False
    assert len(response["conflicts"]) == 1
    _object_of(answer, "new.user")
    record = _current_record(answer)
    assert record["state"] == "undo_failed"


def test_the_apply_mode_refuses_a_malformed_request(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A request that is not one JSON object of the contract is schema."""
    assert answers["apply-schema"]["code"] == "schema"


def test_the_apply_mode_refuses_another_device(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A request for another domain is schema."""
    assert answers["apply-wrong-device"]["code"] == "schema"


def test_the_apply_mode_answers_unavailable_when_the_store_is_locked(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The lock of the transaction store is held for the whole run."""
    assert answers["apply-unavailable"]["code"] == "unavailable"


def test_the_confirm_mode_cancels_the_undo(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A confirm deletes the task and confirms the record."""
    answer = answers["confirm-ok"]
    assert _codes(answer) == ["ok", "ok"]
    assert "task:delete newton-undo-" + TXID in _calls(answer)
    record = _current_record(answer)
    assert record["state"] == "confirmed"


def test_the_record_of_a_transaction_is_on_the_disk_before_the_write(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The record is flushed to the disk, not buffered.

    A record that is in the buffer of the process is a record that a
    power cut loses, and the undo of the change it guards would never
    run.
    """
    answer = answers["apply-ok"]
    flushed = [
        line for line in answer["file_log"] if line.startswith("flush-to-disk ")
    ]
    assert flushed, answer["file_log"]
    assert all(line == "flush-to-disk True" for line in flushed)


def test_the_confirm_mode_refuses_a_value_that_changed(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A confirm of a target that no longer shows the after-image is a conflict."""
    answer = answers["confirm-conflict"]
    assert _codes(answer) == ["ok", "conflict"]
    assert "task:delete newton-undo-" + TXID not in _calls(answer)


def test_the_confirm_mode_refuses_a_transaction_that_is_not_there(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A confirm of an unknown transaction is not_found."""
    assert answers["confirm-not-found"]["code"] == "not_found"


def test_the_confirm_mode_refuses_an_undone_transaction(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A confirm after an undo is a conflict."""
    answer = answers["confirm-after-abort"]
    assert _codes(answer) == ["ok", "ok", "conflict"]


def test_the_confirm_mode_acts_only_on_an_armed_transaction(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A second confirm is a conflict and changes nothing."""
    answer = answers["confirm-twice"]
    assert _codes(answer) == ["ok", "ok", "conflict"]
    assert _calls(answer).count("task:delete newton-undo-" + TXID) == 1


def test_the_confirm_of_a_verified_unlock_answers_ok(
    answers: dict[str, dict[str, Any]],
) -> None:
    """An unlock is confirmed at the apply; the confirm after it answers ok.

    It writes no new generation and deletes no task: an unlock never had one.
    """
    answer = answers["confirm-unlock"]
    assert _codes(answer) == ["ok", "ok"]
    assert _current_record(answer)["state"] == "confirmed"
    assert not [call for call in _calls(answer) if call.startswith("task:")]
    assert sorted(answer["files"]) == [TXID + ".0.json", TXID + ".1.json"]


def test_the_confirm_of_an_unlock_whose_target_changed_is_a_conflict(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The confirm of an unlock still re-reads the target (section 6)."""
    answer = answers["confirm-unlock-changed"]
    assert _codes(answer) == ["ok", "conflict"]


def test_a_confirmed_record_of_a_verb_with_an_undo_is_a_conflict(
    answers: dict[str, dict[str, Any]],
) -> None:
    """Only an unlock answers ok on a confirmed record."""
    answer = answers["confirm-confirmed-uac-clear"]
    assert _codes(answer) == ["conflict"]
    assert sorted(answer["files"]) == [TXID + ".0.json"]


def test_a_failed_confirm_task_delete_leaves_the_record_armed(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The record of the confirmation comes first.

    The confirmation is recorded before the undo task is cancelled, so
    a cancel that fails does not change the answer: the record says
    confirmed, and the task that fires anyway finds a confirmed record
    and does nothing.
    """
    answer = answers["confirm-task-delete-error"]
    assert _codes(answer) == ["ok", "ok", "ok"]
    assert _current_record(answer)["state"] == "confirmed"
    assert "not cancelled" in answer["results"][1]["stderr"]


def test_the_confirm_records_the_confirmation_before_it_cancels_the_task(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A confirmation that cannot be recorded leaves the undo armed.

    The undo task is not cancelled: the change that every controller
    verified can still be put back.
    """
    answer = answers["confirm-record-write-error"]
    assert _codes(answer) == ["ok", "error", "ok"]
    assert "task:delete newton-undo-" + TXID not in _calls(answer)
    assert _current_record(answer)["state"] == "armed"


def test_the_undo_of_a_confirmed_transaction_does_nothing(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The timer of a confirmed transaction finds the record and stops.

    The task of the undo was not cancelled, and it runs anyway: it
    finds the record of the confirmation and it changes nothing.
    """
    answer = answers["confirm-task-delete-error-then-undo"]
    assert _codes(answer) == ["ok", "ok", "ok"]
    response = answer["results"][-1]["response"]
    assert response["restored"] is False
    assert _current_record(answer)["state"] == "confirmed"
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == [
        "66048"
    ]


def test_the_abort_mode_puts_the_before_image_back(
    answers: dict[str, dict[str, Any]],
) -> None:
    """An abort writes the before-image back."""
    answer = answers["abort-ok"]
    assert _codes(answer) == ["ok", "ok"]
    assert answer["results"][1]["response"]["restored"] is True
    assert answer["results"][1]["response"]["conflicts"] == []
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]
    record = _current_record(answer)
    assert record["state"] == "undone"


def test_the_undo_leaves_a_value_that_changed_alone(
    answers: dict[str, dict[str, Any]],
) -> None:
    """An undo that meets a changed value records a conflict."""
    answer = answers["abort-conflict"]
    assert _codes(answer) == ["ok", "ok"]
    response = answer["results"][1]["response"]
    assert response["restored"] is False
    assert len(response["conflicts"]) == 1
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["999999"]
    record = _current_record(answer)
    assert record["state"] == "undo_failed"


def test_the_abort_mode_refuses_a_transaction_that_is_not_there(
    answers: dict[str, dict[str, Any]],
) -> None:
    """An abort of an unknown transaction is not_found."""
    assert answers["abort-not-found"]["code"] == "not_found"


@pytest.mark.parametrize("name", ["abort-after-confirm", "abort-after-refusal"])
def test_the_abort_mode_acts_only_on_an_armed_transaction(
    answers: dict[str, dict[str, Any]], name: str
) -> None:
    """Abort never changes a confirmed or refused record."""
    answer = answers[name]
    assert answer["results"][-1]["code"] == "conflict"


def test_abort_deletes_the_undo_task_once_the_record_is_final(
    answers: dict[str, dict[str, Any]],
) -> None:
    assert "task:delete newton-undo-" + TXID in _calls(answers["abort-ok"])


def test_the_status_mode_answers_the_state(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A status answers the state of the transaction."""
    answer = answers["status-armed"]
    assert _codes(answer) == ["ok", "ok"]
    response = answer["results"][1]["response"]
    assert response["state"] == "armed"
    assert response["undo_at"] == NOW + 600
    assert response["restored"] is False
    assert response["conflicts"] == []


def test_the_status_mode_answers_a_confirmed_transaction(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A status of a confirmed transaction says so."""
    answer = answers["status-confirmed"]
    assert answer["results"][-1]["response"]["state"] == "confirmed"


def test_the_status_mode_refuses_a_transaction_that_is_not_there(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A status of an unknown transaction is not_found."""
    assert answers["status-not-found"]["code"] == "not_found"


def test_the_undo_mode_puts_the_before_image_back(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The undo of the task puts the before-image back."""
    answer = answers["undo-ok"]
    assert _codes(answer) == ["ok", "ok"]
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]
    record = _current_record(answer)
    assert record["state"] == "undone"


def test_the_undo_task_appends_its_terminal_record(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The S4U undo never rewrites its armed record."""
    files = answers["undo-ok"]["files"]
    assert json.loads(files[TXID + ".0.json"])["state"] == "armed"
    assert json.loads(files[TXID + ".1.json"])["state"] == "undone"


def test_the_undo_mode_is_refused_over_ssh(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The undo never runs over an SSH session."""
    assert answers["undo-with-ssh-connection"]["results"][-1]["code"] == "schema"
    assert answers["undo-with-ssh-client"]["results"][-1]["code"] == "schema"


def test_the_undo_mode_refuses_a_transaction_that_is_not_there(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The undo of an unknown transaction is not_found."""
    assert answers["undo-not-found"]["code"] == "not_found"


def test_the_undo_mode_refuses_a_transaction_id_that_is_not_one(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The transaction id is checked before it is used in a path."""
    assert answers["undo-bad-txid"]["code"] == "schema"


@pytest.mark.parametrize("name", ["undo-after-confirm", "undo-after-refusal"])
def test_the_timer_undo_of_a_non_armed_record_is_a_noop(
    answers: dict[str, dict[str, Any]], name: str
) -> None:
    """A late task is harmless and reports that it restored nothing."""
    response = answers[name]["results"][-1]["response"]
    assert response["code"] == "ok"
    assert response["restored"] is False


def test_an_exception_before_the_write_records_refused(
    answers: dict[str, dict[str, Any]],
) -> None:
    answer = answers["apply-register-error-before-write"]
    assert answer["code"] == "unavailable"
    assert _current_record(answer)["state"] == "refused"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_an_exception_after_the_write_restores_and_records_the_truth(
    answers: dict[str, dict[str, Any]],
) -> None:
    answer = answers["apply-readback-error-after-write"]
    assert answer["code"] == "error"
    record = _current_record(answer)
    assert record["state"] == "undone"
    assert record["restored"] is True
    assert "task:delete newton-undo-" + TXID in _calls(answer)
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


def test_the_sweep_undoes_a_record_whose_deadline_has_passed(
    answers: dict[str, dict[str, Any]],
) -> None:
    """Every run undoes the armed records whose deadline has passed."""
    answer = answers["sweep-undoes-the-armed-record"]
    assert _codes(answer) == ["ok", "ok"]
    record = _current_record(answer)
    assert record["state"] == "undone"
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


def test_the_sweep_leaves_a_record_alone_until_its_deadline(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A record whose deadline has not passed is left alone."""
    answer = answers["sweep-leaves-a-record-alone-until-its-deadline"]
    assert _codes(answer) == ["ok", "ok"]
    record = _current_record(answer)
    assert record["state"] == "armed"
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]


def test_a_group_nested_in_a_privileged_group_is_privileged(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The walk of memberOf finds the privileged group under a nested one."""
    answer = answers["nested-privileged-group"]
    assert answer["code"] == "privileged"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_a_cycle_of_memberof_ends_the_walk(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A cycle in memberOf does not stop the helper."""
    answer = answers["memberof-cycle"]
    assert answer["code"] == "ok"
    assert "ldap:modify userAccountControl" in _calls(answer)


def test_every_case_answered(
    answers: dict[str, dict[str, Any]],
) -> None:
    """Every case of the file answered, and no case crashed."""
    for case in _cases():
        answer = answers[case["id"]]
        assert answer["error"] == "", case["id"]
        assert answer["results"], case["id"]


# ---------------------------------------------------------------------------
# the measured shapes of a real domain controller
# ---------------------------------------------------------------------------


def test_the_move_verb_renames_the_object(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A move is a rename: the object lands in the parent of the after-image."""
    answer = answers["move-ok"]
    assert answer["code"] == "ok"
    calls = _calls(answer)
    assert "ldap:modifydn CN=" + SEED_SAM + "," + OU_USERS in " ".join(calls)
    assert "ldap:modify distinguishedName" not in " ".join(calls)
    moved = _object_with_dn(answer, f"CN={SEED_SAM},{OU_OPS}")
    assert moved["sam"] == SEED_LIVE_SAM


def test_the_move_verb_refuses_a_before_image_that_does_not_match(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A move of an object that is somewhere else is a conflict."""
    answer = answers["move-conflict"]
    assert answer["code"] == "conflict"
    assert "ldap:modifydn" not in " ".join(_calls(answer))


def test_the_undo_of_a_move_puts_the_object_back(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The undo of a move renames the object back."""
    answer = answers["move-then-abort"]
    assert _codes(answer) == ["ok", "ok"]
    assert answer["results"][1]["response"]["restored"] is True
    assert answer["results"][1]["response"]["conflicts"] == []
    _object_with_dn(answer, f"CN={SEED_SAM},{OU_USERS}")


def test_the_undo_of_a_move_leaves_a_moved_object_alone(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The undo of a move only renames back when the parent is the new one."""
    answer = answers["move-undo-conflict"]
    assert _codes(answer) == ["ok", "ok"]
    response = answer["results"][1]["response"]
    assert response["restored"] is False
    assert len(response["conflicts"]) == 1
    record = _current_record(answer)
    assert record["state"] == "undo_failed"


def test_the_move_verb_refuses_the_domain_controllers_ou(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The Domain Controllers OU is never a parent of a move."""
    answer = answers["move-into-the-domain-controllers-ou"]
    assert answer["code"] in ("denied", "not_found")
    assert "ldap:modifydn" not in " ".join(_calls(answer))


def test_the_move_verb_refuses_a_parent_that_is_not_a_container(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The new parent of a move is an organizational unit or a container."""
    answer = answers["move-not-a-container"]
    assert answer["code"] == "denied"
    assert "ldap:modifydn" not in " ".join(_calls(answer))


def test_the_maq_verb_writes_the_quota_of_the_domain_head(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A maq writes ms-DS-MachineAccountQuota of the domain head."""
    answer = answers["maq-ok"]
    assert answer["code"] == "ok"
    head = _object_with_dn(answer, DOMAIN_DN)
    assert head["values"]["ms-ds-machineaccountquota"] == ["20"]


def test_a_dc_account_never_loses_its_trust_bit(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The trust bit of a domain controller account is never cleared."""
    answer = answers["apply-denied-dc-account-trust-bit"]
    assert answer["code"] == "denied"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_the_user_create_refuses_a_used_user_principal_name(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A new user may not take the user principal name of another one."""
    answer = answers["apply-user-create-upn-exists"]
    assert answer["code"] == "conflict"
    assert "ldap:add" not in " ".join(_calls(answer))


def test_the_read_of_a_user_create_finds_a_used_user_principal_name(
    answers: dict[str, dict[str, Any]],
) -> None:
    """SPEC-1.4 section 3: absent means no object holds the UPN either."""
    answer = answers["read-user-create-upn-exists"]
    assert answer["code"] == "ok"
    assert answer["response"]["live"] == {"object": "present"}
    free = answers["read-user-create-upn-free"]
    assert free["code"] == "ok"
    assert free["response"]["live"] == {"object": "absent"}


def test_a_user_create_without_a_dns_name_is_an_error(
    answers: dict[str, dict[str, Any]],
) -> None:
    """No user is made with a UPN of 'sam@': the read and the apply refuse."""
    assert answers["read-user-create-no-dns-name"]["code"] == "error"
    answer = answers["apply-user-create-no-dns-name"]
    assert answer["code"] == "error"
    assert "ldap:add" not in " ".join(_calls(answer))


def test_the_token_is_checked_before_the_rules_of_the_verb(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The order of the checks: the token, the window, the replay, the rest."""
    answer = answers["apply-bad-token-before-the-verb-rules"]
    assert answer["code"] == "bad_token"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_a_broken_store_is_an_error_and_not_a_replay(
    answers: dict[str, dict[str, Any]],
) -> None:
    """Only a record that exists is a replay."""
    answer = answers["apply-record-store-error"]
    assert answer["code"] == "error"


def test_a_group_deeper_than_the_cap_is_privileged(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The privilege walk fails closed when it reaches the cap."""
    answer = answers["apply-privileged-deep-group"]
    assert answer["code"] == "privileged"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_a_group_that_cannot_be_read_is_privileged(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The privilege walk fails closed when a group cannot be read."""
    answer = answers["apply-privileged-unreadable-group"]
    assert answer["code"] == "privileged"
    assert "ldap:modify userAccountControl" not in _calls(answer)


def test_the_membership_of_a_group_is_a_base_scope_search(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The presence of a member is a search, never the whole member list."""
    answer = answers["member-add-ok"]
    assert answer["code"] == "ok"
    calls = _calls(answer)
    assert any("ldap:search (member=" in call for call in calls)
    group = _object_of(answer, GROUP_SAM)
    assert group["values"]["member"] == [f"CN={MEMBER_SAM},{OU_USERS}"]


def test_the_removal_of_a_member_writes_the_member_list(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A member-remove deletes the one member of the group."""
    answer = answers["member-remove-ok"]
    assert answer["code"] == "ok"
    group = _object_of(answer, GROUP_SAM)
    assert "member" not in group["values"]


# ---------------------------------------------------------------------------
# the names of the accounts are lowercased
# ---------------------------------------------------------------------------


def test_the_read_mode_answers_the_name_of_an_account_in_lowercase(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The ids of a read carry the name of the directory in lowercase."""
    answer = answers["read-mixed-case-account"]
    assert answer["code"] == "ok"
    ids = answer["response"]["ids"]
    assert ids["sam"] == SEED_SAM
    assert ids["sam"] == ids["sam"].lower()


def test_the_read_mode_answers_the_name_of_the_administrator_in_lowercase(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A real ``Administrator`` comes back as ``administrator``."""
    answer = answers["read-mixed-case-administrator"]
    assert answer["code"] == "ok"
    ids = answer["response"]["ids"]
    assert ids["sam"] == "administrator"
    assert ids["sid"] == ADMIN_SID
    assert ids["guid"] == ADMIN_GUID


def test_the_read_mode_answers_the_names_of_a_group_and_a_member_in_lowercase(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The ids of a membership carry the two names in lowercase."""
    answer = answers["read-mixed-case-members"]
    assert answer["code"] == "ok"
    ids = answer["response"]["ids"]
    assert ids["group_sam"] == GROUP_SAM
    assert ids["member_sam"] == MEMBER_SAM
    for name in ("group_sam", "member_sam"):
        assert ids[name] == ids[name].lower()


def test_an_apply_carries_the_lowercase_name_of_a_mixed_case_account(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The request holds the lowercase name of an account of the directory."""
    answer = answers["apply-mixed-case-account"]
    assert answer["code"] == "ok"
    assert "ldap:modify userAccountControl" in _calls(answer)


def test_an_apply_carries_the_lowercase_names_of_a_group_and_a_member(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The request holds the lowercase names of a group and of a member."""
    answer = answers["apply-mixed-case-members"]
    assert answer["code"] == "ok"
    group = _object_of(answer, GROUP_SAM)
    assert group["values"]["member"] == [f"CN={MEMBER_SAM},{OU_USERS}"]


def test_a_name_that_differs_by_more_than_the_case_is_refused(
    answers: dict[str, dict[str, Any]],
) -> None:
    """A name that is not the name of the account is not found."""
    assert answers["read-a-name-that-differs-by-more-than-the-case"]["code"] == (
        "not_found"
    )
    answer = answers["apply-a-name-that-differs-by-more-than-the-case"]
    assert answer["code"] == "not_found"
    assert "ldap:modify userAccountControl" not in _calls(answer)


# ---------------------------------------------------------------------------
# the answer of a mode is one object, always
# ---------------------------------------------------------------------------


def test_a_leaked_value_makes_the_answer_of_the_mode_an_error(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The entry point answers one object, never a list."""
    answer = answers["apply-with-a-leaking-adapter"]
    assert answer["code"] == "error"
    assert answer["response"] == {"v": 1, "code": "error"}


def test_the_leaked_types_are_named_on_stderr(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The operator sees which types leaked, on stderr only."""
    answer = answers["apply-with-a-leaking-adapter"]
    result = answer["results"][0]
    assert "System.Int32" in result["stderr"]
    assert "System.Int32" not in json.dumps(answer["response"])


def test_the_guard_answers_the_user_create_mode_too(
    answers: dict[str, dict[str, Any]],
) -> None:
    """Every mode goes through the same guard."""
    answer = answers["user-create-with-a-leaking-adapter"]
    assert answer["code"] == "error"
    assert answer["response"] == {"v": 1, "code": "error"}
    assert "System.Int32" in answer["results"][0]["stderr"]


def test_the_write_of_a_leaking_apply_still_happened(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The guard hides the answer, never the write."""
    answer = answers["apply-with-a-leaking-adapter"]
    assert "ldap:modify userAccountControl" in _calls(answer)
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]
