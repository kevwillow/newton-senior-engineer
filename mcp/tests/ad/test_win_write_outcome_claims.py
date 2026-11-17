"""The Windows write helper reports only outcomes the directory makes true.

A record state or answer write.ps1 writes must be one the directory makes
true.  The cases run through the harness of
``test_win_write_modes.py`` in one pwsh process.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from newton_mcp.ad.write import apply as core_apply
from test_win_write_modes import (
    DEVICE,
    ADMINS_DN,
    ADMINS_GUID,
    ADMINS_SID,
    DNS_DOMAIN,
    DOMAIN_DN,
    GROUP_GUID,
    GROUP_SAM,
    GROUP_SID,
    HARNESS,
    MEMBER_GUID,
    MEMBER_SAM,
    MEMBER_SID,
    EXP,
    NBF,
    NOW,
    OU_GUID,
    OU_OPS,
    OU_OPS_GUID,
    OU_USERS,
    PARENT_GUID,
    SEED_GUID,
    SEED_SAM,
    SEED_SID,
    TXID,
    _apply,
    _calls,
    _codes,
    _current_record,
    _directory,
    _mode,
    _move,
    _object,
    _object_of,
    _object_with_dn,
    _pwsh,
    _read,
    _stored_record,
)


POISON = "fedcba9876543210fedcba9876543210"
#: A second and a third transaction on the same target.
TXID_B = "1111111111111111aaaaaaaaaaaaaaaa"
TXID_C = "2222222222222222bbbbbbbbbbbbbbbb"
MEMBER_DN = f"CN={MEMBER_SAM},{OU_USERS}"
DELETE_TASK = "task:delete newton-undo-" + TXID


def _seed(**fields: Any) -> dict[str, Any]:
    values: dict[str, Any] = {"uac": 4260352, "parent": OU_USERS}
    values.update(fields)
    return _object(f"CN={SEED_SAM},{OU_USERS}", SEED_GUID, SEED_SID, SEED_SAM, **values)


def _unlock_apply() -> str:
    return _apply(
        "unlock",
        target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
        before={"lockout": 1000},
        after={"lockout": 0},
        window=120,
        risk="LOW",
    )


def _member_add() -> str:
    return _apply(
        "member-add",
        target={
            "group_guid": GROUP_GUID, "group_sid": GROUP_SID, "group_sam": GROUP_SAM,
            "member_guid": MEMBER_GUID, "member_sid": MEMBER_SID, "member_sam": MEMBER_SAM,
        },
        before={"member": "absent"},
        after={"member": "present"},
    )


def _poisoned_record() -> str:
    """An expired armed record whose target is not there and whose next
    generation cannot be written: its undo throws out of the undo."""
    payload = json.loads(_apply(txid=POISON))
    payload.pop("token", None)
    payload["target"] = {"guid": "00000000-0000-4000-8000-000000000000",
                         "sid": "S-1-5-21-1-2-3-9999", "sam": "gone", "bit": 4194304}
    return json.dumps({
        "v": 1, "txid": POISON, "request": payload, "created": None,
        "state": "armed", "undo_at": NOW - 1, "restored": False, "conflicts": [],
    })


def _user_create_apply() -> str:
    return _apply(
        "user-create",
        target={"parent_guid": PARENT_GUID, "sam": "new.user"},
        before={"object": "absent"},
        after={"object": "present"},
        secret="a-very-secret-password",
    )


NEW_USER_DN = f"CN=new.user,{DOMAIN_DN}"
MOVED_NEW_USER_DN = f"CN=new.user,{OU_USERS}"
#: The objectGUID of somebody else's account at the planned DN.
REPLACEMENT_GUID = "cc2b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"


def _armed_user_create_without_facts() -> str:
    """An armed user-create record with no created facts: the helper
    stopped after the add and before it wrote them."""
    payload = json.loads(_user_create_apply())
    payload.pop("token", None)
    payload.pop("secret", None)
    return json.dumps({
        "v": 1, "txid": TXID, "request": payload, "created": None,
        "state": "armed", "undo_at": NOW + 600, "restored": False, "conflicts": [],
    })


def _answered_record(undo_at: int) -> str:
    """An armed record whose write the server answered with a result code
    (53): the atomic write wrote nothing of Newton's."""
    payload = json.loads(_apply())
    payload.pop("token", None)
    return json.dumps({
        "v": 1, "txid": TXID, "request": payload, "created": None,
        "state": "armed", "undo_at": undo_at, "restored": False, "conflicts": [],
        "answered": 53,
    })


#: A txid that sorts before TXID, so the sweep meets the malformed record first.
FIRST = "00000000000000000000000000000000"


def _malformed_record() -> str:
    """An expired armed record whose request is not an object."""
    return json.dumps({
        "v": 1, "txid": FIRST, "request": "not-a-request", "created": None,
        "state": "armed", "undo_at": NOW - 1, "restored": False, "conflicts": [],
    })


COMPUTER_GUID = "c09619ff-8b86-d011-b42d-00c04fc964ff"
COMPUTER_SID = "S-1-5-21-1-2-3-1120"
COMPUTER_SAM = "ws01$"
PRIV_GUID = "c19619ff-8b86-d011-b42d-00c04fc964ff"
PRIV_SID = "S-1-5-21-1-2-3-1121"
PRIV_SAM = "admin2"


def _computer(**fields: Any) -> dict[str, Any]:
    """A computer account of a workstation (WORKSTATION_TRUST_ACCOUNT)."""
    values: dict[str, Any] = {
        "object_class": ["top", "person", "organizationalPerson", "user", "computer"],
        "uac": 4096, "primary_group_id": 515,
        "token_groups": ["S-1-5-21-1-2-3-515"], "parent": OU_USERS,
    }
    values.update(fields)
    return _object(f"CN=ws01,{OU_USERS}", COMPUTER_GUID, COMPUTER_SID, COMPUTER_SAM, **values)


def _computer_apply(verb: str, before: int, after: int) -> str:
    return _apply(
        verb,
        target={"guid": COMPUTER_GUID, "sid": COMPUTER_SID, "sam": COMPUTER_SAM},
        before={"uac": before},
        after={"uac": after},
    )


def _privileged_admin() -> dict[str, Any]:
    """A locked-out member of Domain Admins with adminCount 1."""
    return _object(f"CN={PRIV_SAM},{OU_USERS}", PRIV_GUID, PRIV_SID, PRIV_SAM,
                   admin_count=1, lockout=1000, member_of=[ADMINS_DN],
                   token_groups=["S-1-5-21-1-2-3-513", ADMINS_SID], parent=OU_USERS)


def _privileged_unlock_apply() -> str:
    return _apply(
        "unlock",
        target={"guid": PRIV_GUID, "sid": PRIV_SID, "sam": PRIV_SAM},
        before={"lockout": 1000},
        after={"lockout": 0},
        window=120,
        risk="HIGH",
    )


def _cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    def add(name: str, **fields: Any) -> None:
        cases.append({"id": name, **fields})

    # a write with no server result code
    add("no-response", ldap=_directory(objects=[_seed(modify_error_no_response=1)]),
        requests=[{"raw": _apply(), "stage": "write"}])
    add("unlock-no-response",
        ldap=_directory(objects=[_seed(lockout=1000, modify_error_no_response=1)]),
        requests=[{"raw": _unlock_apply(), "stage": "write"}])
    # somebody else's value after a failed write
    add("third-value",
        ldap=_directory(objects=[_seed(race_values=["4096"], modify_error=1)]),
        requests=[{"raw": _apply(), "stage": "write"}])
    add("member-added-by-someone-else",
        ldap=_directory(objects=[
            _object(f"CN={GROUP_SAM},{OU_USERS}", GROUP_GUID, GROUP_SID, GROUP_SAM,
                    object_class=["top", "group"], parent=OU_USERS,
                    race_values=[MEMBER_DN], modify_error=20),
            _object(MEMBER_DN, MEMBER_GUID, MEMBER_SID, MEMBER_SAM, parent=OU_USERS),
        ]),
        requests=[{"raw": _member_add(), "stage": "write"}])
    add("unlock-third-value",
        ldap=_directory(objects=[_seed(lockout=1000, race_values=["2000"], modify_error=1)]),
        requests=[{"raw": _unlock_apply(), "stage": "write"}])
    # the record of the undo cannot be written
    add("undo-record-not-written", ldap=_directory(), read_error_after_modifies=2,
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"}])
    # a refusal whose state write fails leaves nothing armed
    add("refusal-state-write-fails",
        ldap=_directory(objects=[_seed(uac=66048)]),
        record_is_directory_file=TXID + ".1.json",
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write", "now": NOW + 601}])
    # an undo whose answer was lost
    add("undo-answer-lost", ldap=_directory(objects=[_seed(lost_answer_on_modify=2)]),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"}])
    add("undo-answer-lost-and-no-reread",
        ldap=_directory(objects=[_seed(lost_answer_on_modify=2)],
                        search_errors_after_modifies={"after": 2, "count": 50}),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"}])
    # the write landed, its read-back failed and the undo cannot read
    add("read-back-and-undo-unreadable",
        ldap=_directory(search_errors_after_modifies={"after": 1, "count": 50}),
        requests=[{"raw": _apply(), "stage": "write"}])
    # one record whose undo throws never stops the sweep
    add("poisoned-record", ldap=_directory(),
        store_files={POISON + ".0.json": _poisoned_record()},
        record_is_directory_file=POISON + ".1.json",
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write"}])
    # a landed unlock whose confirmed record cannot be written
    add("unlock-lost-answer-confirm-not-written",
        ldap=_directory(objects=[_seed(lockout=1000, lost_answer_on_modify=1)]),
        record_create_fails_once=TXID + ".1.json",
        requests=[{"raw": _unlock_apply(), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write"}])
    add("unlock-ok-confirm-not-written",
        ldap=_directory(objects=[_seed(lockout=1000)]),
        record_create_fails_once=TXID + ".1.json",
        requests=[{"raw": _unlock_apply(), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write"}])
    # a third value after a write with no server answer
    add("third-value-no-response",
        ldap=_directory(objects=[_seed(race_values=["4096"], modify_error_no_response=1)]),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write", "now": NOW + 601}])
    add("unlock-third-value-no-response",
        ldap=_directory(objects=[_seed(lockout=1000, race_values=["2000"],
                                       modify_error_no_response=1)]),
        requests=[{"raw": _unlock_apply(), "stage": "write"}])
    # a re-read that cannot name a value is unreadable, never a third value
    add("move-parent-unreadable-no-response",
        ldap=_directory(objects=[
            _seed(modifydn_no_response_drops_parent=1),
            _object(OU_USERS, OU_GUID, None, None, object_class=["top", "organizationalUnit"]),
            _object(OU_OPS, OU_OPS_GUID, None, None, object_class=["top", "organizationalUnit"]),
        ]),
        requests=[{"raw": _move(), "stage": "write"}])
    add("uac-unreadable-lost-answer",
        ldap=_directory(objects=[_seed(drift_after_write="", lost_answer_on_modify=1)]),
        requests=[{"raw": _apply(), "stage": "write"}])
    # an undo with no server answer while the after-image is still there
    add("undo-no-response-after-image",
        ldap=_directory(objects=[_seed(no_response_on_modify=2)]),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"}])
    # an undo the server refused whose re-read cannot read the uac
    add("undo-refused-uac-unreadable-abort",
        ldap=_directory(objects=[_seed(refused_unreadable_on_modify=2)]),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"}])
    add("undo-refused-uac-unreadable-task",
        ldap=_directory(objects=[_seed(refused_unreadable_on_modify=2)]),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"stage": "undo", "undo": TXID}])
    # an unlock whose write succeeded and whose read-back right after throws
    add("unlock-ok-read-back-throws",
        ldap=_directory(objects=[_seed(lockout=1000)], search_errors_after_write=1),
        requests=[{"raw": _unlock_apply(), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write"}])
    # an unlock left armed (its write landed, the re-read failed), then the
    # sweep after undo_at and an abort
    for name, second in (("armed-unlock-sweep", _mode("status")),
                         ("armed-unlock-abort", _mode("abort"))):
        add(name,
            ldap=_directory(objects=[_seed(lockout=1000, modify_error_after_write=1)],
                            search_errors_after_write=1),
            trace_undo_record=True,
            requests=[{"raw": _unlock_apply(), "stage": "write", "now": NOW},
                      {"raw": second, "stage": "write", "now": NOW + 900}])
    # a created user another admin renamed, or deleted, before its undo
    rename = {"stage": "directory",
              "rename_sam": {"from": "new.user", "to": "renamed.user"}}
    add("user-create-renamed-then-abort", ldap=_directory(),
        requests=[{"raw": _user_create_apply(), "stage": "write"}, rename,
                  {"raw": _mode("abort"), "stage": "write"}])
    add("user-create-renamed-then-task", ldap=_directory(),
        requests=[{"raw": _user_create_apply(), "stage": "write"}, rename,
                  {"stage": "undo", "undo": TXID}])
    add("user-create-deleted-then-abort", ldap=_directory(),
        requests=[{"raw": _user_create_apply(), "stage": "write"},
                  {"stage": "directory", "delete_sam": "new.user"},
                  {"raw": _mode("abort"), "stage": "write"}])
    add("user-create-renamed-unreadable-abort", ldap=_directory(),
        requests=[{"raw": _user_create_apply(), "stage": "write"},
                  {**rename, "fail_guid_searches_of_sam": "renamed.user"},
                  {"raw": _mode("abort"), "stage": "write"}])
    # a user-create that landed with no created facts
    add("user-create-add-answer-lost", ldap=_directory(lost_answer_on_add=True),
        requests=[{"raw": _user_create_apply(), "stage": "write"}])
    add("user-create-armed-without-facts-task",
        ldap=_directory(objects=[_object(NEW_USER_DN, "4f9619ff-8b86-d011-b42d-00c04fc964ff",
                                         "S-1-5-21-1-2-3-9999", "new.user", uac=514,
                                         parent=DOMAIN_DN,
                                         upn="new.user@" + DNS_DOMAIN)]),
        store_files={TXID + ".0.json": _armed_user_create_without_facts()},
        requests=[{"stage": "undo", "undo": TXID}])
    # a user-create with no created GUID: somebody renamed the account,
    # or it is still at its planned name
    renamed_without_facts = _object(NEW_USER_DN, "4f9619ff-8b86-d011-b42d-00c04fc964ff",
                                    "S-1-5-21-1-2-3-9999", "renamed.user", uac=514,
                                    parent=DOMAIN_DN, upn="renamed.user@" + DNS_DOMAIN)
    for way, request in (("task", {"stage": "undo", "undo": TXID}),
                         ("abort", {"raw": _mode("abort"), "stage": "write"})):
        add("user-create-without-facts-renamed-" + way,
            ldap=_directory(objects=[renamed_without_facts]),
            store_files={TXID + ".0.json": _armed_user_create_without_facts()},
            requests=[request])
    add("user-create-armed-without-facts-abort",
        ldap=_directory(objects=[_object(NEW_USER_DN, "4f9619ff-8b86-d011-b42d-00c04fc964ff",
                                         "S-1-5-21-1-2-3-9999", "new.user", uac=514,
                                         parent=DOMAIN_DN,
                                         upn="new.user@" + DNS_DOMAIN)]),
        store_files={TXID + ".0.json": _armed_user_create_without_facts()},
        requests=[{"raw": _mode("abort"), "stage": "write"}])
    # the apply's own cleanup of a new user whose facts are missing: the
    # delete landed and its answer was lost
    add("user-create-missing-facts-delete-answer-lost",
        ldap=_directory(created_missing_guid=True, ldap_delete_lost_answer=True),
        requests=[{"raw": _user_create_apply(), "stage": "write"}])
    # Newton's after-image after an error the server answered: somebody
    # else made the same change, and Newton's atomic write wrote nothing
    add("after-image-answered",
        ldap=_directory(objects=[_seed(race_values=["66048"], modify_error=53)]),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write", "now": NOW + 601}])
    add("unlock-after-image-answered",
        ldap=_directory(objects=[_seed(lockout=1000, race_values=["0"], modify_error=53)]),
        requests=[{"raw": _unlock_apply(), "stage": "write"}])
    add("after-image-no-answer",
        ldap=_directory(objects=[_seed(lost_answer_on_modify=1)]),
        requests=[{"raw": _apply(), "stage": "write"}])
    # the same branches when the refused record cannot be written: the
    # marker of the answered write (generation 1) lands, the refused
    # record (generation 2) does not
    sweep = {"raw": _mode("status"), "stage": "write", "now": NOW + 601}
    add("after-image-answered-refused-not-written",
        ldap=_directory(objects=[_seed(race_values=["66048"], modify_error=53)]),
        record_is_directory_file=TXID + ".2.json",
        requests=[{"raw": _apply(), "stage": "write"}, sweep])
    add("third-value-answered-refused-not-written",
        ldap=_directory(objects=[_seed(race_values=["4096"], modify_error=1)]),
        record_is_directory_file=TXID + ".2.json",
        requests=[{"raw": _apply(), "stage": "write"}, sweep])
    add("conflict-answered-refused-not-written",
        ldap=_directory(objects=[
            _object(f"CN={GROUP_SAM},{OU_USERS}", GROUP_GUID, GROUP_SID, GROUP_SAM,
                    object_class=["top", "group"], parent=OU_USERS,
                    race_values=[MEMBER_DN], modify_error=20),
            _object(MEMBER_DN, MEMBER_GUID, MEMBER_SID, MEMBER_SAM, parent=OU_USERS),
        ]),
        record_is_directory_file=TXID + ".2.json",
        requests=[{"raw": _member_add(), "stage": "write"}, sweep])
    # the store takes neither the mark nor the refused record (generation 1
    # can never be created): the record stays armed with no mark
    blocked = TXID + ".1.json"
    add("after-image-answered-unmarked",
        ldap=_directory(objects=[_seed(race_values=["66048"], modify_error=53)]),
        record_is_directory_file=blocked, requests=[{"raw": _apply(), "stage": "write"}])
    add("third-value-answered-unmarked",
        ldap=_directory(objects=[_seed(race_values=["4096"], modify_error=1)]),
        record_is_directory_file=blocked, requests=[{"raw": _apply(), "stage": "write"}])
    add("before-image-answered-unmarked",
        ldap=_directory(objects=[_seed(modify_error=53)]),
        record_is_directory_file=blocked, requests=[{"raw": _apply(), "stage": "write"}])
    add("unreadable-answered-unmarked",
        ldap=_directory(objects=[_seed(refused_unreadable_on_modify=1)]),
        record_is_directory_file=blocked, requests=[{"raw": _apply(), "stage": "write"}])
    add("conflict-answered-unmarked",
        ldap=_directory(objects=[
            _object(f"CN={GROUP_SAM},{OU_USERS}", GROUP_GUID, GROUP_SID, GROUP_SAM,
                    object_class=["top", "group"], parent=OU_USERS,
                    race_values=[MEMBER_DN], modify_error=20),
            _object(MEMBER_DN, MEMBER_GUID, MEMBER_SID, MEMBER_SAM, parent=OU_USERS),
        ]),
        record_is_directory_file=blocked, requests=[{"raw": _member_add(), "stage": "write"}])
    add("no-response-store-full",
        ldap=_directory(objects=[_seed(modify_error_no_response=1)]),
        record_is_directory_file=blocked, requests=[{"raw": _apply(), "stage": "write"}])
    add("unlock-answered-store-full",
        ldap=_directory(objects=[_seed(lockout=1000, modify_error=53)]),
        record_is_directory_file=blocked, requests=[{"raw": _unlock_apply(), "stage": "write"}])
    # the undo task cannot be registered, so nothing is sent, and the store
    # takes no refused record after the armed one
    add("task-register-fails-store-full",
        ldap=_directory(objects=[_seed()]), scheduler_register_error=True,
        record_is_directory_file=blocked, requests=[{"raw": _apply(), "stage": "write"}])
    # the mark fails once and the refused record then lands
    add("after-image-answered-mark-fails-once",
        ldap=_directory(objects=[_seed(race_values=["66048"], modify_error=53)]),
        record_create_fails_once=blocked, requests=[{"raw": _apply(), "stage": "write"}])
    # the mark fails once and the refused record then lands, with the
    # before-image there: the answer is the write's own code, not a conflict
    add("before-image-answered-mark-fails-once",
        ldap=_directory(objects=[_seed(modify_error=53)]),
        record_create_fails_once=blocked, requests=[{"raw": _apply(), "stage": "write"}])
    # an armed record whose write the server answered, met by the sweep, the
    # task and an abort while the after-image (somebody else's) is there
    for way, request in (("sweep", sweep), ("task", {"stage": "undo", "undo": TXID}),
                         ("abort", {"raw": _mode("abort"), "stage": "write"})):
        add("answered-record-" + way,
            ldap=_directory(objects=[_seed(uac=66048)]),
            store_files={TXID + ".0.json": _answered_record(NOW - 1)},
            requests=[request])
    # a throw from inside the failed-write handler after a write with no
    # server answer
    add("handler-throws-after-no-answer",
        ldap=_directory(objects=[_seed(modify_error_no_response=1)]),
        throw_in_live_readable=True,
        requests=[{"raw": _apply(), "stage": "write"}])
    # a malformed record never stops the sweep or the mode that runs it
    add("malformed-record-apply", ldap=_directory(),
        store_files={FIRST + ".0.json": _malformed_record()},
        requests=[{"raw": _apply(), "stage": "write"}])
    add("malformed-record-sweep", ldap=_directory(),
        store_files={FIRST + ".0.json": _malformed_record()},
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write", "now": NOW + 601}])
    # a record whose bytes reached the file and whose flush to the disk then
    # threw: the record is there, and the write threw all the same
    gen0, gen1, gen2 = TXID + ".0.json", TXID + ".1.json", TXID + ".2.json"
    add("armed-flush-fails", ldap=_directory(objects=[_seed()]),
        record_flush_fails_once=gen0,
        requests=[{"raw": _apply(), "stage": "write"}, sweep])
    add("armed-flush-fails-refused-blocked", ldap=_directory(objects=[_seed()]),
        record_flush_fails_once=gen0, record_is_directory_file=gen1,
        requests=[{"raw": _apply(), "stage": "write"}])
    add("unlock-armed-flush-fails-refused-blocked",
        ldap=_directory(objects=[_seed(lockout=1000)]),
        record_flush_fails_once=gen0, record_is_directory_file=gen1,
        requests=[{"raw": _unlock_apply(), "stage": "write"}])
    add("after-image-answered-refused-flush-fails",
        ldap=_directory(objects=[_seed(race_values=["66048"], modify_error=53)]),
        record_flush_fails_once=gen2, requests=[{"raw": _apply(), "stage": "write"}])
    add("conflict-answered-refused-flush-fails",
        ldap=_directory(objects=[
            _object(f"CN={GROUP_SAM},{OU_USERS}", GROUP_GUID, GROUP_SID, GROUP_SAM,
                    object_class=["top", "group"], parent=OU_USERS,
                    race_values=[MEMBER_DN], modify_error=20),
            _object(MEMBER_DN, MEMBER_GUID, MEMBER_SID, MEMBER_SAM, parent=OU_USERS),
        ]),
        record_flush_fails_once=gen2, requests=[{"raw": _member_add(), "stage": "write"}])
    add("after-image-answered-mark-flush-fails-refused-blocked",
        ldap=_directory(objects=[_seed(race_values=["66048"], modify_error=53)]),
        record_flush_fails_once=gen1, record_is_directory_file=gen2,
        requests=[{"raw": _apply(), "stage": "write"}, sweep])
    add("task-register-fails-refused-flush-fails",
        ldap=_directory(objects=[_seed()]), scheduler_register_error=True,
        record_flush_fails_once=gen1, requests=[{"raw": _apply(), "stage": "write"}])
    add("confirm-flush-fails", ldap=_directory(objects=[_seed()]),
        record_flush_fails_once=gen1,
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("confirm"), "stage": "write"}])
    add("abort-flush-fails", ldap=_directory(objects=[_seed()]),
        record_flush_fails_once=gen1,
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"}])
    # the armed record's flush threw and the store then cannot be read: the
    # helper cannot tell what the disk holds, so it acts as if the armed
    # record landed
    add("armed-flush-fails-store-unreadable", ldap=_directory(objects=[_seed()]),
        record_flush_fails_once=gen0, store_reads_fail_once_there=gen0,
        requests=[{"raw": _apply(), "stage": "write"}])
    add("armed-flush-fails-store-unreadable-refused-blocked",
        ldap=_directory(objects=[_seed()]),
        record_flush_fails_once=gen0, store_reads_fail_once_there=gen0,
        record_is_directory_file=gen1,
        requests=[{"raw": _apply(), "stage": "write"}])
    add("unlock-armed-flush-fails-store-unreadable-refused-blocked",
        ldap=_directory(objects=[_seed(lockout=1000)]),
        record_flush_fails_once=gen0, store_reads_fail_once_there=gen0,
        record_is_directory_file=gen1,
        requests=[{"raw": _unlock_apply(), "stage": "write"}])
    # another writer created the armed record's generation first: its file is
    # not this record, so it is never taken for the armed record that landed
    add("armed-collision", ldap=_directory(objects=[_seed()]), record_collision=TXID,
        requests=[{"raw": _apply(), "stage": "write"}])
    # a conflict whose refused record landed, then a store that cannot be read
    add("conflict-answered-store-unreadable-after",
        ldap=_directory(objects=[
            _object(f"CN={GROUP_SAM},{OU_USERS}", GROUP_GUID, GROUP_SID, GROUP_SAM,
                    object_class=["top", "group"], parent=OU_USERS,
                    race_values=[MEMBER_DN], modify_error=20),
            _object(MEMBER_DN, MEMBER_GUID, MEMBER_SID, MEMBER_SAM, parent=OU_USERS),
        ]),
        store_reads_fail_once_there=gen2,
        requests=[{"raw": _member_add(), "stage": "write"}])
    # a generation whose write failed after CreateNew made the file (a full
    # disk): an empty file is left above the armed record, which the store
    # cannot delete (its ACL has no Delete right)
    add("confirm-torn", ldap=_directory(objects=[_seed()]),
        record_write_torn_once=gen1,
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _mode("confirm"), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write"},
                  sweep])
    torn_store = {gen0: _stored_record("armed"), gen1: ""}
    add("torn-above-armed-status", ldap=_directory(objects=[_seed(uac=66048)]),
        store_files=torn_store, requests=[{"raw": _mode("status"), "stage": "write"}])
    add("torn-above-armed-task", ldap=_directory(objects=[_seed(uac=66048)]),
        store_files=torn_store, requests=[{"stage": "undo", "undo": TXID}])
    add("torn-above-armed-sweep", ldap=_directory(objects=[_seed(uac=66048)]),
        store_files=torn_store, requests=[sweep])
    # the README's "covered by tests" marks: a computer account disabled and
    # enabled through the apply, confirmed or undone, and a privileged
    # account (adminCount 1, a member of Domain Admins) unlocked
    for verb, before, after in (("disable", 4096, 4098), ("enable", 4098, 4096)):
        raw = _computer_apply(verb, before, after)
        for ending in ("confirm", "abort"):
            add(f"computer-{verb}-{ending}",
                ldap=_directory(objects=[_computer(uac=before)]),
                requests=[{"raw": raw, "stage": "write"},
                          {"raw": _mode(ending), "stage": "write"}])
        add(f"computer-{verb}-task",
            ldap=_directory(objects=[_computer(uac=before)]),
            requests=[{"raw": raw, "stage": "write"}, {"stage": "undo", "undo": TXID}])
    admin_ldap = _directory(objects=[_privileged_admin(), _object(
        ADMINS_DN, ADMINS_GUID, ADMINS_SID, "domain-admins",
        object_class=["top", "group"], parent=DOMAIN_DN)])
    add("privileged-unlock",
        ldap=admin_ldap,
        requests=[{"raw": _privileged_unlock_apply(), "stage": "write"},
                  {"raw": _mode("confirm"), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write", "now": NOW + 3601}])
    add("privileged-unlock-task",
        ldap=admin_ldap,
        requests=[{"raw": _privileged_unlock_apply(), "stage": "write"},
                  {"stage": "undo", "undo": TXID}])
    # the mark of an answered write lands and the refused record above it is
    # torn: the current record is the marked one, so the answer is not unmarked
    add("answered-mark-lands-refused-torn",
        ldap=_directory(objects=[_seed(modify_error=53)]),
        record_write_torn_once=gen2, requests=[{"raw": _apply(), "stage": "write"}])
    add("torn-above-armed-abort", ldap=_directory(objects=[_seed(uac=66048)]),
        store_files=torn_store, requests=[{"raw": _mode("abort"), "stage": "write"}])
    # a complete generation that carries the mark of an answered write, whose
    # read throws (a sharing violation): the reader never passes over it to
    # the armed generation below, whose undo would write the before-image
    # over somebody else's after-image
    unreadable_store = {gen0: _stored_record("armed"), gen1: _answered_record(NOW + 600)}
    for way, request in (
        ("status", {"raw": _mode("status"), "stage": "write"}),
        ("task", {"stage": "undo", "undo": TXID, "now": NOW + 601}),
        ("sweep", {"raw": _read(), "stage": "write", "now": NOW + 601}),
        ("abort", {"raw": _mode("abort"), "stage": "write"}),
        ("confirm", {"raw": _mode("confirm"), "stage": "write"}),
    ):
        add("unreadable-marked-" + way, ldap=_directory(objects=[_seed(uac=66048)]),
            store_files=unreadable_store, record_read_throws=gen1, requests=[request])
        # the listing of the store throws (a denied access): no record is
        # taken for absent either
        add("unlisted-store-" + way, ldap=_directory(objects=[_seed(uac=66048)]),
            store_files=unreadable_store, store_list_throws=True, requests=[request])
    add("unlisted-store-apply", ldap=_directory(objects=[_seed(uac=66048)]),
        store_files=unreadable_store, store_list_throws=True,
        requests=[{"raw": _apply(), "stage": "write"}])
    # an armed record (an unanswered write whose re-read shows the
    # before-image) and a later change of the same target
    add("armed-then-same-target", ldap=_directory(objects=[_seed(modify_error_no_response=1)]),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _apply(txid=TXID_B), "stage": "write"},
                  {"raw": _mode("confirm", txid=TXID_B), "stage": "write"},
                  {"raw": _mode("status"), "stage": "write", "now": NOW + 601}])
    add("armed-then-other-verb", ldap=_directory(objects=[_seed(modify_error_no_response=1)]),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _apply("disable", target={"guid": SEED_GUID, "sid": SEED_SID,
                                                    "sam": SEED_SAM},
                                 before={"uac": 4260352}, after={"uac": 4260354},
                                 txid=TXID_B), "stage": "write"}])
    add("armed-then-settled", ldap=_directory(objects=[_seed(modify_error_no_response=1)]),
        requests=[{"raw": _apply(), "stage": "write"},
                  {"raw": _apply(txid=TXID_C, nbf=NBF + 600, exp=EXP + 600),
                   "stage": "write", "now": NOW + 601}])
    add("armed-unlock-then-change",
        ldap=_directory(objects=[_seed(lockout=1000, modify_error_no_response=1)]),
        requests=[{"raw": _unlock_apply(), "stage": "write"},
                  {"raw": _apply(txid=TXID_B), "stage": "write"}])
    add("armed-unreadable-then-change", ldap=_directory(objects=[_seed()]),
        store_files={gen0: _stored_record("armed")}, record_read_throws=gen0,
        requests=[{"raw": _apply(txid=TXID_B), "stage": "write"}])
    # the apply's own cleanup of a new user whose facts are missing, after
    # somebody moved it away and created another account at its DN
    moved = {"to": MOVED_NEW_USER_DN, "replacement_guid": REPLACEMENT_GUID,
             "replacement_sam": "other.user"}
    add("user-create-moved-replaced-no-guid",
        ldap=_directory(created_missing_guid=True, moved_and_replaced_after_add=moved),
        requests=[{"raw": _user_create_apply(), "stage": "write"}])
    add("user-create-moved-replaced-guid",
        ldap=_directory(created_missing_usn=True, moved_and_replaced_after_add=moved),
        requests=[{"raw": _user_create_apply(), "stage": "write"}])
    add("user-create-moved-replaced-guid-delete-lost",
        ldap=_directory(created_missing_usn=True, moved_and_replaced_after_add=moved,
                        ldap_delete_lost_answer=True),
        requests=[{"raw": _user_create_apply(), "stage": "write"}])
    # every write names its object by its GUID: between the read that found
    # the object and the write, somebody moves it away and creates another
    # account at its DN
    for refused in (False, True):
        extra: dict[str, Any] = {"ldap_delete_error": 50} if refused else {}
        add("cleanup-replaced-during-delete" + ("-refused" if refused else ""),
            ldap=_directory(created_missing_usn=True,
                            replace_during=_replace_during("delete", NEW_USER_DN,
                                                           MOVED_NEW_USER_DN), **extra),
            requests=[{"raw": _user_create_apply(), "stage": "write"}])
    for way, request in (("task", {"stage": "undo", "undo": TXID}),
                         ("abort", {"raw": _mode("abort"), "stage": "write"})):
        add("user-create-undo-replaced-during-delete-" + way,
            ldap=_directory(replace_during=_replace_during("delete", NEW_USER_DN,
                                                           MOVED_NEW_USER_DN)),
            requests=[{"raw": _user_create_apply(), "stage": "write"}, request])
        add("uac-undo-replaced-during-modify-" + way,
            ldap=_directory(replace_during=_replace_during("modify", SEED_DN,
                                                           MOVED_SEED_DN, nth=2)),
            requests=[{"raw": _apply(), "stage": "write"}, request])
    add("user-create-undo-replaced-during-delete-refused",
        ldap=_directory(ldap_delete_error=50,
                        replace_during=_replace_during("delete", NEW_USER_DN,
                                                       MOVED_NEW_USER_DN)),
        requests=[{"raw": _user_create_apply(), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"}])
    add("uac-apply-replaced-during-modify",
        ldap=_directory(replace_during=_replace_during("modify", SEED_DN, MOVED_SEED_DN)),
        requests=[{"raw": _apply(), "stage": "write"}])
    add("member-apply-replaced-during-modify",
        ldap=_directory(replace_during=_replace_during("modify", GROUP_DN, MOVED_GROUP_DN)),
        requests=[{"raw": _member_add(), "stage": "write"}])
    add("member-undo-replaced-during-modify",
        ldap=_directory(replace_during=_replace_during("modify", GROUP_DN, MOVED_GROUP_DN,
                                                       nth=2)),
        requests=[{"raw": _member_add(), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"}])
    add("move-apply-replaced-during-modifydn",
        ldap=_directory(replace_during=_replace_during("modifydn", SEED_DN, MOVED_SEED_DN)),
        requests=[{"raw": _move(), "stage": "write"}])
    add("move-undo-replaced-during-modifydn",
        ldap=_directory(replace_during=_replace_during("modifydn", SEED_OPS_DN, MOVED_SEED_DN,
                                                       nth=2)),
        requests=[{"raw": _move(), "stage": "write"},
                  {"raw": _mode("abort"), "stage": "write"}])
    _unreadable_cases(add)
    _same_target_cases(add)
    _replica_cases(add)
    return cases


SEED_DN = f"CN={SEED_SAM},{OU_USERS}"
SEED_OPS_DN = f"CN={SEED_SAM},{OU_OPS}"
#: Where somebody moves an account or a group Newton writes.
MOVED_SEED_DN = f"CN={SEED_SAM},{DOMAIN_DN}"
GROUP_DN = f"CN={GROUP_SAM},{OU_USERS}"
MOVED_GROUP_DN = f"CN={GROUP_SAM},{DOMAIN_DN}"


def _replace_during(kind: str, dn: str, new_dn: str, nth: int = 1) -> dict[str, Any]:
    """The ``nth`` write of ``kind``: before the fake finds its object,
    somebody moves the object at ``dn`` to ``new_dn`` and creates another
    account (``REPLACEMENT_GUID``) at ``dn``."""
    return {"kind": kind, "from": dn, "to": new_dn, "nth": nth,
            "replacement_guid": REPLACEMENT_GUID, "replacement_sam": "other.user"}


@pytest.fixture(scope="module")
def answers(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    pwsh = _pwsh()
    path = tmp_path_factory.mktemp("win-write-outcomes") / "cases.json"
    path.write_text(json.dumps({"cases": _cases()}), encoding="utf-8")
    finished = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-File", str(HARNESS), str(path)],
        capture_output=True, text=True, timeout=600, check=False,
    )
    if finished.returncode != 0:
        pytest.fail(f"the harness failed: {finished.stderr.strip()[:2000]}")
    return {str(case["id"]): case for case in json.loads(finished.stdout)["cases"]}


def test_a_write_with_no_server_answer_stays_armed_with_its_task(answers: dict[str, Any]) -> None:
    """A client timeout: no result code, the re-read shows the before-image,
    and the modify may still commit.  Never refused: the record stays armed
    and the undo task registered, so the task puts back whatever lands."""
    answer = answers["no-response"]
    assert answer["code"] == "error"
    assert _current_record(answer)["state"] == "armed"
    assert DELETE_TASK not in _calls(answer)


def test_an_unlock_with_no_server_answer_stays_armed(answers: dict[str, Any]) -> None:
    answer = answers["unlock-no-response"]
    assert answer["code"] == "error"
    assert _current_record(answer)["state"] == "armed"


def test_a_third_value_after_a_failed_write_is_a_conflict_never_undone(answers: dict[str, Any]) -> None:
    answer = answers["third-value"]
    assert answer["code"] == "conflict"
    assert answer["response"]["live"] == {"uac": 4096}
    record = _current_record(answer)
    assert record["state"] == "refused"
    assert record["conflicts"] != []
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4096"]
    assert DELETE_TASK in _calls(answer)


def test_a_member_someone_else_added_is_never_removed(answers: dict[str, Any]) -> None:
    """The add of a value that is there answers 20: a conflict, nothing of
    Newton's was written, and the other admin's membership stays."""
    answer = answers["member-added-by-someone-else"]
    assert answer["code"] == "conflict"
    assert _current_record(answer)["state"] == "refused"
    assert _object_of(answer, GROUP_SAM)["values"]["member"] == [MEMBER_DN]


def test_an_unlock_is_confirmed_only_on_its_after_image(answers: dict[str, Any]) -> None:
    answer = answers["unlock-third-value"]
    assert _current_record(answer)["state"] != "confirmed"
    assert answer["code"] == "conflict"


def test_an_undo_whose_record_cannot_be_written_keeps_its_task(answers: dict[str, Any]) -> None:
    """The undo ran, its record could not be written: the abort never
    answers ok restored=true over an armed record, and the task stays."""
    answer = answers["undo-record-not-written"]
    assert _codes(answer) == ["ok", "error"]
    assert _current_record(answer)["state"] == "armed"
    assert DELETE_TASK not in _calls(answer)


def test_a_refusal_whose_state_write_fails_leaves_nothing_the_sweep_undoes(
    answers: dict[str, Any],
) -> None:
    """The before-image does not match (someone else already made the
    change): a conflict.  The refusal is recorded without a second
    generation, and the sweep after undo_at never writes the value back."""
    answer = answers["refusal-state-write-fails"]
    assert _codes(answer) == ["conflict", "ok"]
    assert answer["results"][1]["response"]["state"] == "refused"
    assert "ldap:modify userAccountControl" not in _calls(answer)
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]


def test_an_undo_whose_answer_was_lost_is_recorded_by_the_directory(answers: dict[str, Any]) -> None:
    answer = answers["undo-answer-lost"]
    assert _codes(answer) == ["ok", "ok"]
    assert answer["results"][1]["response"]["restored"] is True
    record = _current_record(answer)
    assert record["state"] == "undone"
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


def test_an_undo_whose_answer_was_lost_and_cannot_be_read_is_never_still_written(
    answers: dict[str, Any],
) -> None:
    answer = answers["undo-answer-lost-and-no-reread"]
    assert _codes(answer) == ["ok", "error"]
    assert _current_record(answer)["state"] == "armed"
    assert DELETE_TASK not in _calls(answer)


def test_a_record_whose_undo_throws_never_stops_the_sweep(answers: dict[str, Any]) -> None:
    answer = answers["poisoned-record"]
    assert _codes(answer) == ["ok", "ok"]
    assert answer["results"][1]["response"]["state"] == "armed"


def test_a_landed_write_whose_undo_cannot_read_is_never_recorded_undo_failed(
    answers: dict[str, Any],
) -> None:
    """The write landed, the read-back after it failed, and the undo run at
    once cannot read the target either: the record stays armed with its
    task, never undo_failed (which tells the owner it is still written)."""
    answer = answers["read-back-and-undo-unreadable"]
    assert answer["code"] == "error"
    assert _current_record(answer)["state"] == "armed"
    assert DELETE_TASK not in _calls(answer)


def test_a_landed_unlock_whose_confirmed_record_fails_is_never_refused(
    answers: dict[str, Any],
) -> None:
    """The unlock landed and its answer was lost; the re-read shows the
    after-image and the confirmed record cannot be written.  The record is
    never refused (nothing changed) while the account is unlocked."""
    answer = answers["unlock-lost-answer-confirm-not-written"]
    assert answer["results"][0]["code"] not in ("conflict", "refused")
    assert answer["results"][1]["response"]["state"] != "refused"
    assert _object_of(answer, SEED_SAM)["values"]["lockouttime"] == ["0"]


def test_an_unlock_whose_confirmed_record_fails_is_never_refused(
    answers: dict[str, Any],
) -> None:
    answer = answers["unlock-ok-confirm-not-written"]
    assert answer["results"][1]["response"]["state"] != "refused"
    assert _object_of(answer, SEED_SAM)["values"]["lockouttime"] == ["0"]


def test_a_third_value_after_a_write_with_no_server_answer_is_unknown_never_refused(
    answers: dict[str, Any],
) -> None:
    """No result code, and the re-read shows neither image: another change
    reached the target and Newton's write may have landed before it.  The
    record is never refused; the undo is disarmed so it never writes over
    the other change, the answer is not a conflict, and the sweep after
    undo_at writes nothing."""
    answer = answers["third-value-no-response"]
    assert _codes(answer) == ["error", "ok"]
    first = answer["results"][0]["response"]
    assert first["live"] == {"uac": 4096}
    status = answer["results"][1]["response"]
    assert status["state"] == "undo_failed"
    assert status["restored"] is False
    assert status["conflicts"] != []
    assert DELETE_TASK in _calls(answer)
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4096"]


def test_an_unlock_with_a_third_lockout_and_no_server_answer_is_unknown_never_refused(
    answers: dict[str, Any],
) -> None:
    answer = answers["unlock-third-value-no-response"]
    assert answer["code"] == "error"
    assert answer["response"]["live"] == {"lockout": 2000}
    assert _current_record(answer)["state"] == "armed"
    assert _object_of(answer, SEED_SAM)["values"]["lockouttime"] == ["2000"]


def test_a_failed_move_whose_parent_cannot_be_read_stays_armed(answers: dict[str, Any]) -> None:
    """No result code, and the object's current parent cannot be read: the
    outcome is unknown, so the record stays armed with its task."""
    answer = answers["move-parent-unreadable-no-response"]
    assert answer["code"] == "error"
    assert _current_record(answer)["state"] == "armed"
    assert DELETE_TASK not in _calls(answer)


def test_a_lost_answer_whose_re_read_cannot_read_the_uac_stays_armed(
    answers: dict[str, Any],
) -> None:
    """The write landed and its answer was lost; the re-read cannot read
    userAccountControl.  That is no value at all: the record stays armed
    with its task, never recorded as somebody else's change."""
    answer = answers["uac-unreadable-lost-answer"]
    assert answer["code"] == "error"
    assert _current_record(answer)["state"] == "armed"
    assert DELETE_TASK not in _calls(answer)


def test_an_undo_with_no_server_answer_while_the_after_image_is_there_stays_armed(
    answers: dict[str, Any],
) -> None:
    """The undo modify got no answer and the target still shows the
    after-image: the undo may still land, so the record stays armed with
    its task, never undo_failed (still written)."""
    answer = answers["undo-no-response-after-image"]
    assert _codes(answer) == ["ok", "error"]
    assert _current_record(answer)["state"] == "armed"
    assert DELETE_TASK not in _calls(answer)
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]


@pytest.mark.parametrize("way", ["abort", "task"])
def test_a_failed_undo_whose_re_read_cannot_read_the_uac_stays_armed(
    answers: dict[str, Any], way: str
) -> None:
    """The undo modify failed and the re-read shows a userAccountControl
    of 0, which is no value at all: the outcome cannot be read, so the
    record stays armed with its task, never undo_failed with a conflict."""
    answer = answers["undo-refused-uac-unreadable-" + way]
    assert _codes(answer) == ["ok", "error"]
    record = _current_record(answer)
    assert record["state"] == "armed"
    assert not record.get("conflicts")
    assert DELETE_TASK not in _calls(answer)


def test_an_unlock_whose_read_back_throws_after_a_good_write_is_confirmed(
    answers: dict[str, Any],
) -> None:
    """The unlock write succeeded and the read-back right after it threw:
    the account stays unlocked and the record is confirmed, never undone or
    refused."""
    answer = answers["unlock-ok-read-back-throws"]
    assert _object_of(answer, SEED_SAM)["values"]["lockouttime"] == ["0"]
    assert answer["results"][1]["response"]["state"] == "confirmed"
    assert _current_record(answer)["state"] == "confirmed"


def test_the_sweep_never_runs_the_undo_of_an_armed_unlock(answers: dict[str, Any]) -> None:
    """The sweep after undo_at skips an armed unlock before its undo is
    called at all."""
    answer = answers["armed-unlock-sweep"]
    assert _current_record(answer)["state"] == "armed"
    assert "undo-record " + TXID not in _calls(answer)
    assert _object_of(answer, SEED_SAM)["values"]["lockouttime"] == ["0"]


def test_the_abort_of_an_armed_unlock_is_refused_with_conflict(answers: dict[str, Any]) -> None:
    """An unlock has no undo: its abort answers conflict, never ok, and the
    undo of the record is never called."""
    answer = answers["armed-unlock-abort"]
    assert answer["results"][1]["code"] == "conflict"
    assert "undo-record " + TXID not in _calls(answer)
    assert _current_record(answer)["state"] == "armed"
    assert _object_of(answer, SEED_SAM)["values"]["lockouttime"] == ["0"]


# ---- the undo of a user-create reads the created object by its GUID ---------


@pytest.mark.parametrize("way", ["abort", "task"])
def test_the_undo_of_a_created_user_someone_renamed_is_undo_failed_never_undone(
    answers: dict[str, Any], way: str
) -> None:
    """Another admin renamed the account Newton created (its
    sAMAccountName and user principal name): the undo leaves it, and the
    re-read looks the account up by its GUID, so it is still there and the
    record is undo_failed with it named, never undone."""
    answer = answers["user-create-renamed-then-" + way]
    assert _codes(answer) == ["ok", "ok", "ok"]
    record = _current_record(answer)
    guid = str(record["created"]["guid"])
    assert guid
    response = answer["results"][2]["response"]
    assert response["restored"] is False
    if way == "abort":
        assert response["conflicts"] == [guid]
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [guid]
    _object_of(answer, "renamed.user")
    assert not any(call.startswith("ldap:delete") for call in _calls(answer))


def test_the_undo_of_a_created_user_someone_deleted_is_undone(answers: dict[str, Any]) -> None:
    answer = answers["user-create-deleted-then-abort"]
    assert _codes(answer) == ["ok", "ok", "ok"]
    response = answer["results"][2]["response"]
    assert response["restored"] is True
    assert response["conflicts"] == []
    assert _current_record(answer)["state"] == "undone"


def test_the_undo_of_a_created_user_whose_guid_read_fails_stays_armed(
    answers: dict[str, Any],
) -> None:
    """The created account cannot be looked up again: the outcome is
    unknown, so the record stays armed with its task."""
    answer = answers["user-create-renamed-unreadable-abort"]
    assert _codes(answer) == ["ok", "ok", "error"]
    assert _current_record(answer)["state"] == "armed"
    assert DELETE_TASK not in _calls(answer)
    _object_of(answer, "renamed.user")


def test_a_landed_user_create_whose_answer_was_lost_names_its_dn_in_conflicts(
    answers: dict[str, Any],
) -> None:
    """The add landed and its answer was lost, so no created GUID is
    recorded: the undo cannot identify the object and leaves it, and the
    conflict names its DN, never an empty name."""
    answer = answers["user-create-add-answer-lost"]
    assert answer["code"] == "error"
    record = _current_record(answer)
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [NEW_USER_DN]
    _object_of(answer, "new.user")
    assert not any(call.startswith("ldap:delete") for call in _calls(answer))


def test_the_task_undo_of_a_user_create_with_no_facts_names_its_dn(
    answers: dict[str, Any],
) -> None:
    answer = answers["user-create-armed-without-facts-task"]
    assert answer["code"] == "ok"
    assert answer["response"]["restored"] is False
    record = _current_record(answer)
    assert record["state"] == "undo_failed"
    assert record["conflicts"] == [NEW_USER_DN]
    _object_of(answer, "new.user")


# ---- the after-image after an error the server answered ---------------------


def test_the_after_image_after_an_error_the_server_answered_is_refused_never_undone(
    answers: dict[str, Any],
) -> None:
    """The server answered the write with a result code, so the atomic
    modify wrote nothing: the after-image there is somebody else's change.
    The record is refused with the conflict, the task goes, the answer is
    conflict with live, and the other admin's value stays."""
    answer = answers["after-image-answered"]
    assert answer["code"] == "conflict"
    assert answer["response"]["live"] == {"uac": 66048}
    record = _current_record(answer)
    assert record["state"] == "refused"
    assert record["restored"] is False
    assert record["conflicts"] != []
    assert DELETE_TASK in _calls(answer)
    assert answer["results"][1]["response"]["state"] == "refused"
    assert _calls(answer).count("ldap:modify userAccountControl") == 1
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]


def test_an_unlock_after_image_after_an_error_the_server_answered_is_refused(
    answers: dict[str, Any],
) -> None:
    """Newton's unlock did not land: somebody else unlocked the account.
    Refused with the conflict, never confirmed."""
    answer = answers["unlock-after-image-answered"]
    assert answer["code"] == "conflict"
    assert answer["response"]["live"] == {"lockout": 0}
    record = _current_record(answer)
    assert record["state"] == "refused"
    assert record["conflicts"] != []


def test_the_after_image_after_a_write_with_no_server_answer_is_undone_now(
    answers: dict[str, Any],
) -> None:
    """Control: no result code, and the after-image is Newton's own write
    whose answer was lost, so the undo runs now."""
    answer = answers["after-image-no-answer"]
    assert answer["code"] == "error"
    assert _current_record(answer)["state"] == "undone"
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


# ---- a malformed record never stops the sweep -------------------------------


def test_a_malformed_record_never_stops_the_mode_that_runs_the_sweep(
    answers: dict[str, Any],
) -> None:
    answer = answers["malformed-record-apply"]
    assert answer["code"] == "ok"
    assert answer["files"][FIRST + ".0.json"] == _malformed_record()


def test_a_malformed_record_never_stops_the_undo_of_another_record(
    answers: dict[str, Any],
) -> None:
    answer = answers["malformed-record-sweep"]
    assert _codes(answer) == ["ok", "ok"]
    assert answer["results"][1]["response"]["state"] == "undone"
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]
    assert answer["files"][FIRST + ".0.json"] == _malformed_record()


# ---- a user-create with no recorded GUID is never undone by a name lookup ---


@pytest.mark.parametrize("way", ["task", "abort"])
def test_the_undo_of_a_user_create_with_no_guid_whose_account_was_renamed_is_undo_failed(
    answers: dict[str, Any], way: str
) -> None:
    """No created GUID is recorded and somebody renamed the account (its
    sAMAccountName and user principal name): a lookup by the planned names
    finds nothing, which never proves the account gone.  The record is
    undo_failed with the planned DN as the conflict, never undone."""
    answer = answers["user-create-without-facts-renamed-" + way]
    assert answer["code"] == "ok"
    assert answer["response"]["restored"] is False
    record = _current_record(answer)
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [NEW_USER_DN]
    _object_of(answer, "renamed.user")
    assert not any(call.startswith("ldap:delete") for call in _calls(answer))


def test_the_abort_of_a_user_create_with_no_guid_still_at_its_name_is_undo_failed(
    answers: dict[str, Any],
) -> None:
    answer = answers["user-create-armed-without-facts-abort"]
    assert answer["code"] == "ok"
    assert answer["response"]["restored"] is False
    record = _current_record(answer)
    assert record["state"] == "undo_failed"
    assert record["conflicts"] == [NEW_USER_DN]
    _object_of(answer, "new.user")


def test_a_cleanup_of_a_new_user_with_no_facts_whose_delete_answer_was_lost_is_undo_failed(
    answers: dict[str, Any],
) -> None:
    """The apply could not read the new user's facts, so it deleted the DN
    its add named; the delete landed and its answer was lost.  The DN now
    reads empty, but with no GUID that never proves the account gone: the
    record is undo_failed with the DN as the conflict, never undone."""
    answer = answers["user-create-missing-facts-delete-answer-lost"]
    assert answer["code"] == "error"
    record = _current_record(answer)
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [NEW_USER_DN]


# ---- an error the server answered never leaves an undo that runs ------------


@pytest.mark.parametrize(("case", "attribute", "value"), [
    ("after-image-answered-refused-not-written", "useraccountcontrol", ["66048"]),
    ("third-value-answered-refused-not-written", "useraccountcontrol", ["4096"]),
    ("conflict-answered-refused-not-written", "member", [MEMBER_DN]),
])
def test_an_answered_write_whose_refused_record_fails_is_never_a_conflict_and_never_undone(
    answers: dict[str, Any], case: str, attribute: str, value: list[str]
) -> None:
    """The server answered the write, so nothing of Newton's was written, and
    the refused record could not be written.  The task is cancelled anyway,
    the answer is an error (Newton reads the armed record and reports
    apply_unknown, never conflict: nothing written while the store says
    armed), and the sweep after undo_at never writes the before-image over
    the other admin's value."""
    answer = answers[case]
    assert answer["results"][0]["code"] == "error"
    assert DELETE_TASK in _calls(answer)
    record = _current_record(answer)
    assert record["state"] == "armed"
    assert record["answered"] != 0
    assert answer["results"][1]["code"] == "ok"
    obj = GROUP_SAM if attribute == "member" else SEED_SAM
    assert _object_of(answer, obj)["values"][attribute] == value
    modifies = [call for call in _calls(answer) if call.startswith("ldap:modify")]
    assert len(modifies) == 1


@pytest.mark.parametrize("case", [
    "after-image-answered-unmarked",
    "third-value-answered-unmarked",
    "before-image-answered-unmarked",
    "unreadable-answered-unmarked",
    "conflict-answered-unmarked",
])
def test_an_answered_write_whose_store_takes_neither_the_mark_nor_the_refused_record_answers_unmarked(
    answers: dict[str, Any], case: str
) -> None:
    """The server answered the write, so nothing of Newton's was written,
    and the store took neither the mark nor the refused record.  The record
    on the disk is armed with no mark, so a later sweep cannot tell it from
    a write whose answer was lost: the answer says so (``unmarked``), is
    never ok or conflict, and Newton reports it apply_unknown."""
    answer = answers[case]
    assert answer["code"] not in ("ok", "conflict")
    assert answer["response"].get("unmarked") is True
    record = _current_record(answer)
    assert record["state"] == "armed"
    assert "answered" not in record


def test_a_task_that_cannot_be_registered_whose_refused_record_fails_answers_unmarked(
    answers: dict[str, Any],
) -> None:
    """Nothing was sent, but the record on the disk still reads armed with
    no task: the sweep at the next request cannot tell it from a write that
    landed, so the answer says unmarked and Newton tells the owner."""
    answer = answers["task-register-fails-store-full"]
    assert answer["code"] == "unavailable"
    assert answer["response"].get("unmarked") is True
    assert _current_record(answer)["state"] == "armed"
    assert not any(call.startswith("ldap:modify") for call in _calls(answer))


@pytest.mark.parametrize("case", ["no-response-store-full", "unlock-answered-store-full"])
def test_a_write_with_no_answer_or_an_unlock_is_never_unmarked(
    answers: dict[str, Any], case: str
) -> None:
    """A write with no server answer carries no mark by design (it may land
    and the undo must run), and an unlock has no undo: neither is unmarked."""
    answer = answers[case]
    assert "unmarked" not in (answer.get("response") or {})


def test_an_answered_write_whose_mark_fails_and_refused_record_lands_is_not_unmarked(
    answers: dict[str, Any],
) -> None:
    """The mark did not land and the refused record did: the record is
    settled, so the answer is the conflict with no ``unmarked``."""
    answer = answers["after-image-answered-mark-fails-once"]
    assert answer["code"] == "conflict"
    assert "unmarked" not in answer["response"]
    assert _current_record(answer)["state"] == "refused"


def test_an_answered_error_whose_mark_fails_and_refused_record_lands_is_not_unmarked(
    answers: dict[str, Any],
) -> None:
    """The server answered 53 with the before-image still there: the mark
    did not land and the refused record did.  The record reads refused with
    no mark, so the answer (the write's own code, which Add-NewtonUnmarked
    reads after) never says unmarked."""
    answer = answers["before-image-answered-mark-fails-once"]
    assert answer["code"] == "error"
    assert "unmarked" not in answer["response"]
    record = _current_record(answer)
    assert record["state"] == "refused"
    assert record.get("answered") is None


@pytest.mark.parametrize("way", ["sweep", "task", "abort"])
def test_an_armed_record_whose_write_the_server_answered_is_never_undone(
    answers: dict[str, Any], way: str
) -> None:
    """The record says the server answered the apply's write: nothing of
    Newton's was written, so the sweep, the task and an abort write nothing
    (the after-image there is somebody else's) and the record is refused."""
    answer = answers["answered-record-" + way]
    assert not any(call.startswith("ldap:modify") for call in _calls(answer))
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]
    assert _current_record(answer)["state"] == "refused"
    if way == "abort":
        assert answer["code"] == "conflict"


def test_a_throw_inside_the_failed_write_handler_after_no_answer_stays_armed(
    answers: dict[str, Any],
) -> None:
    """The write got no answer from the server and may still land; the
    handler of its failure then threw.  The record stays armed with its
    task, never refused (which says the write was never sent)."""
    answer = answers["handler-throws-after-no-answer"]
    assert answer["code"] == "error"
    assert _current_record(answer)["state"] == "armed"
    assert DELETE_TASK not in _calls(answer)


# ---- a record that landed although its write threw ---------------------------


def _modifies(answer: dict[str, Any]) -> list[str]:
    return [call for call in _calls(answer) if call.startswith("ldap:modify")]


def test_an_armed_record_whose_flush_fails_is_rewritten_refused_and_nothing_is_sent(
    answers: dict[str, Any],
) -> None:
    """The armed record reached the disk and its flush threw.  The helper
    never assumes the disk holds nothing: the record reads armed, so it is
    written refused, nothing is sent, and the sweep after undo_at writes
    nothing."""
    answer = answers["armed-flush-fails"]
    assert _codes(answer) == ["error", "ok"]
    assert "unmarked" not in answer["response"]
    assert _current_record(answer)["state"] == "refused"
    assert _modifies(answer) == []


def test_an_armed_record_whose_flush_fails_and_whose_refused_record_fails_answers_unmarked(
    answers: dict[str, Any],
) -> None:
    answer = answers["armed-flush-fails-refused-blocked"]
    assert answer["code"] == "error"
    assert answer["response"].get("unmarked") is True
    assert _current_record(answer)["state"] == "armed"
    assert _modifies(answer) == []


def test_an_armed_unlock_whose_flush_fails_and_whose_refused_record_fails_is_never_unmarked(
    answers: dict[str, Any],
) -> None:
    answer = answers["unlock-armed-flush-fails-refused-blocked"]
    assert answer["code"] == "error"
    assert "unmarked" not in answer["response"]
    assert _modifies(answer) == []


@pytest.mark.parametrize("case", [
    "after-image-answered-refused-flush-fails",
    "conflict-answered-refused-flush-fails",
])
def test_an_answered_write_whose_refused_record_landed_with_a_flush_error_is_a_conflict(
    answers: dict[str, Any], case: str
) -> None:
    """The refused record reached the disk and its flush threw: the disk
    reads refused, so the answer is the conflict."""
    answer = answers[case]
    assert answer["code"] == "conflict"
    assert "unmarked" not in answer["response"]
    assert _current_record(answer)["state"] == "refused"
    assert DELETE_TASK in _calls(answer)


def test_an_answered_mark_whose_flush_fails_and_refused_record_fails_is_not_unmarked(
    answers: dict[str, Any],
) -> None:
    answer = answers["after-image-answered-mark-flush-fails-refused-blocked"]
    assert answer["results"][0]["code"] == "error"
    assert "unmarked" not in answer["response"]
    record = _current_record(answer)
    assert record["state"] == "armed"
    assert record["answered"] == 53
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]
    assert len(_modifies(answer)) == 1


@pytest.mark.parametrize("case", [
    "after-image-answered-refused-not-written",
    "third-value-answered-refused-not-written",
    "conflict-answered-refused-not-written",
])
def test_an_answered_write_whose_mark_lands_and_refused_record_fails_is_not_unmarked(
    answers: dict[str, Any], case: str
) -> None:
    """The store took the mark and not the refused record: the disk says the
    server answered, so the answer never says unmarked."""
    assert "unmarked" not in answers[case]["response"]


def test_a_task_that_cannot_be_registered_whose_refused_record_landed_is_not_unmarked(
    answers: dict[str, Any],
) -> None:
    answer = answers["task-register-fails-refused-flush-fails"]
    assert answer["code"] == "unavailable"
    assert "unmarked" not in answer["response"]
    assert _current_record(answer)["state"] == "refused"


def test_a_confirm_whose_record_landed_with_a_flush_error_answers_ok(
    answers: dict[str, Any],
) -> None:
    answer = answers["confirm-flush-fails"]
    assert _codes(answer) == ["ok", "ok"]
    assert _current_record(answer)["state"] == "confirmed"
    assert DELETE_TASK in _calls(answer)


def test_an_abort_whose_undone_record_landed_with_a_flush_error_answers_ok(
    answers: dict[str, Any],
) -> None:
    answer = answers["abort-flush-fails"]
    assert _codes(answer) == ["ok", "ok"]
    assert answer["results"][1]["response"]["restored"] is True
    assert _current_record(answer)["state"] == "undone"


def test_a_conflict_whose_store_cannot_be_read_after_is_never_unmarked(
    answers: dict[str, Any],
) -> None:
    """A conflict is answered only once the refused record was written: a
    store that cannot be read afterwards never adds unmarked to it."""
    answer = answers["conflict-answered-store-unreadable-after"]
    assert answer["code"] == "conflict"
    assert "unmarked" not in answer["response"]


def test_an_armed_record_whose_flush_fails_and_whose_read_back_fails_is_written_refused(
    answers: dict[str, Any],
) -> None:
    """The armed record's flush threw and the read-back of the store then
    throws too.  The helper cannot tell what the disk holds, so it never
    takes that for "nothing landed": it writes the record refused, sends
    nothing, and the disk reads refused."""
    answer = answers["armed-flush-fails-store-unreadable"]
    assert answer["code"] == "error"
    assert "unmarked" not in answer["response"]
    assert _current_record(answer)["state"] == "refused"
    assert _modifies(answer) == []


def test_an_armed_record_whose_read_back_fails_and_whose_refused_record_fails_answers_unmarked(
    answers: dict[str, Any],
) -> None:
    """The flush threw, the read-back threw and the refused record cannot be
    written: the disk may read armed for a write that was never sent, so the
    answer says unmarked."""
    answer = answers["armed-flush-fails-store-unreadable-refused-blocked"]
    assert answer["code"] == "error"
    assert answer["response"].get("unmarked") is True
    assert _current_record(answer)["state"] == "armed"
    assert _modifies(answer) == []


def test_an_armed_unlock_whose_read_back_fails_is_never_unmarked(
    answers: dict[str, Any],
) -> None:
    answer = answers["unlock-armed-flush-fails-store-unreadable-refused-blocked"]
    assert answer["code"] == "error"
    assert "unmarked" not in answer["response"]
    assert _modifies(answer) == []


def test_an_armed_record_another_writer_created_first_is_never_taken_for_this_one(
    answers: dict[str, Any],
) -> None:
    answer = answers["armed-collision"]
    assert answer["code"] == "error"
    assert "unmarked" not in answer["response"]
    assert sorted(answer["files"]) == [TXID + ".0.json"]
    assert _modifies(answer) == []


# ---- a torn generation above the armed record ---------------------------------


def _generation(answer: dict[str, Any], n: int) -> str:
    return str(answer["files"][f"{TXID}.{n}.json"])


def test_a_confirm_whose_generation_is_torn_leaves_the_change_armed_and_found(
    answers: dict[str, Any],
) -> None:
    """The confirm's generation was created and its write failed (a full
    disk), leaving an empty file above the armed record.  The status still
    reads armed, never not_found, and the sweep still finds the record and
    puts the before-image back."""
    answer = answers["confirm-torn"]
    assert _generation(answer, 1) == ""
    codes = _codes(answer)
    assert codes[0] == "ok"
    assert codes[1] != "ok"
    assert answer["results"][2]["code"] == "ok"
    assert answer["results"][2]["response"]["state"] == "armed"
    assert answer["results"][3]["response"]["state"] == "undone"
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


@pytest.mark.parametrize("way", ["status", "task", "sweep", "abort"])
def test_a_torn_generation_never_hides_the_armed_record(
    answers: dict[str, Any], way: str,
) -> None:
    answer = answers["torn-above-armed-" + way]
    result = answer["results"][0]
    assert result["code"] == "ok", result
    if way == "status":
        assert result["response"]["state"] == "armed"
        return
    assert _current_record(answer)["state"] == "undone"
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]


def test_a_torn_refused_record_above_the_mark_is_not_unmarked(answers: dict[str, Any]) -> None:
    """The mark of the answered write landed and the refused record above it
    was torn: the record that parses carries the mark, so the undo writes
    nothing and the answer carries no unmarked."""
    answer = answers["answered-mark-lands-refused-torn"]
    assert _generation(answer, 2) == ""
    assert json.loads(_generation(answer, 1))["answered"] == 53
    assert answer["code"] != "ok"
    assert "unmarked" not in answer["response"]


# ---- a generation that cannot be read ----------------------------------------


@pytest.mark.parametrize("way", ["status", "task", "sweep", "abort", "confirm"])
def test_a_marked_generation_that_cannot_be_read_is_never_passed_over(
    answers: dict[str, Any], way: str,
) -> None:
    """The newest generation is complete and carries the mark of a write the
    server answered, and its read throws (a sharing violation).  Only a
    generation that was read and does not parse is passed over: this one
    stops the reader.  Nothing writes the before-image over the after-image
    there (somebody else's), no generation is added, the task stays, and the
    answer is the unknown state, never ok or not_found (the sweep's own mode
    still answers)."""
    answer = answers["unreadable-marked-" + way]
    assert _modifies(answer) == []
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]
    assert f"{TXID}.2.json" not in answer["files"]
    assert DELETE_TASK not in _calls(answer)
    code = answer["results"][0]["code"]
    if way == "sweep":
        assert code == "ok", answer["results"][0]
        return
    assert code == "error", answer["results"][0]


@pytest.mark.parametrize("way", ["status", "task", "sweep", "abort", "confirm", "apply"])
def test_a_store_that_cannot_be_listed_is_never_taken_for_empty(
    answers: dict[str, Any], way: str,
) -> None:
    """The listing of the transaction store throws: no record is taken for
    absent.  Nothing is written, the task stays, and the answer is the
    unknown state, never not_found (the sweep's own mode still answers)."""
    answer = answers["unlisted-store-" + way]
    assert _modifies(answer) == []
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["66048"]
    assert f"{TXID}.2.json" not in answer["files"]
    assert DELETE_TASK not in _calls(answer)
    code = answer["results"][0]["code"]
    if way == "sweep":
        assert code == "ok", answer["results"][0]
        return
    assert code == "error", answer["results"][0]


# ---- the README's "covered by tests" marks -------------------------------------


def _uac(answer: dict[str, Any], sam: str) -> list[str]:
    return _object_of(answer, sam)["values"]["useraccountcontrol"]


@pytest.mark.parametrize("verb, before, after", [("disable", "4096", "4098"),
                                                 ("enable", "4098", "4096")])
def test_a_computer_account_is_disabled_or_enabled_and_confirmed(
    answers: dict[str, Any], verb: str, before: str, after: str,
) -> None:
    answer = answers[f"computer-{verb}-confirm"]
    assert _codes(answer) == ["ok", "ok"]
    assert _current_record(answer)["state"] == "confirmed"
    assert DELETE_TASK in _calls(answer)
    assert _uac(answer, COMPUTER_SAM) == [after]


@pytest.mark.parametrize("ending", ["abort", "task"])
@pytest.mark.parametrize("verb, before", [("disable", "4096"), ("enable", "4098")])
def test_a_computer_account_disable_or_enable_is_undone(
    answers: dict[str, Any], verb: str, before: str, ending: str,
) -> None:
    answer = answers[f"computer-{verb}-{ending}"]
    assert _codes(answer) == ["ok", "ok"]
    assert _current_record(answer)["state"] == "undone"
    assert _uac(answer, COMPUTER_SAM) == [before]


def test_a_privileged_account_is_unlocked_and_never_undone(answers: dict[str, Any]) -> None:
    """An unlock of a member of Domain Admins (adminCount 1) is applied at
    the HIGH risk the helper derives, and nothing puts the lockout back: the
    abort is refused and the sweep leaves it."""
    answer = answers["privileged-unlock"]
    codes = _codes(answer)
    assert codes[0] == "ok"
    assert codes[1] == "ok"
    assert codes[2] == "conflict"
    assert _current_record(answer)["state"] == "confirmed"
    assert _object_of(answer, PRIV_SAM)["values"]["lockouttime"] == ["0"]
    assert not any(call.startswith("task:register") for call in _calls(answer))


def test_the_undo_task_of_a_privileged_unlock_never_locks_it_again(
    answers: dict[str, Any],
) -> None:
    answer = answers["privileged-unlock-task"]
    assert _codes(answer)[0] == "ok"
    assert _object_of(answer, PRIV_SAM)["values"]["lockouttime"] == ["0"]
    assert _current_record(answer)["state"] == "confirmed"


# ---- an armed record never undoes a later confirmed change of its target ----


def _record_of(answer: dict[str, Any], txid: str) -> dict[str, Any]:
    """The current record of one transaction (its highest generation)."""
    names = [name for name in answer["files"]
             if name.startswith(txid + ".") and name.endswith(".json")]
    if not names:
        raise AssertionError(f"the transaction {txid} has no record")
    best = max(names, key=lambda name: int(name[len(txid) + 1:-5] or 0))
    return json.loads(answer["files"][best])


def _ldap_modifies(answer: dict[str, Any]) -> int:
    return len([call for call in _calls(answer) if call.startswith("ldap:modify")])


def test_an_armed_record_never_undoes_a_later_confirmed_change_of_its_target(
    answers: dict[str, Any],
) -> None:
    """A stays armed after a write with no answer whose re-read shows the
    before-image.  B, the same change of the same target, is applied and
    confirmed when the DC takes it.  At A's undo_at the undo must not write
    the before-image over B's confirmed change."""
    answer = answers["armed-then-same-target"]
    live = _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"]
    if _record_of(answer, TXID_B)["state"] == "confirmed":
        assert live == ["66048"]
    else:
        assert live == ["4260352"]


def test_an_apply_while_another_armed_record_names_the_target_is_a_conflict(
    answers: dict[str, Any],
) -> None:
    """The guard: B is refused with conflict (live, armed) before anything is
    armed or written, and A's undo at its undo_at changes nothing."""
    answer = answers["armed-then-same-target"]
    second = answer["results"][1]["response"]
    assert second["code"] == "conflict", second
    assert second["armed"] is True
    assert second["live"] == {"uac": 4260352}
    assert _record_of(answer, TXID_B)["state"] == "refused"
    assert "task:register newton-undo-" + TXID_B not in _calls(answer)
    # A's write and A's undo, an exact-old-value modify the fake refuses (the
    # before-image is there): nothing of B's was ever sent.
    assert _ldap_modifies(answer) == 2
    assert _object_of(answer, SEED_SAM)["values"]["useraccountcontrol"] == ["4260352"]
    assert _current_record(answer)["state"] == "undone"


def test_an_armed_change_of_the_same_attribute_by_another_verb_is_a_conflict(
    answers: dict[str, Any],
) -> None:
    second = answers["armed-then-other-verb"]["results"][1]["response"]
    assert second["code"] == "conflict", second
    assert second["armed"] is True


def test_a_target_takes_a_new_change_once_its_armed_record_settles(
    answers: dict[str, Any],
) -> None:
    answer = answers["armed-then-settled"]
    assert answer["results"][1]["response"]["code"] == "ok", answer["results"][1]
    assert _current_record(answer)["state"] == "undone"


def test_an_armed_unlock_never_blocks_a_change_of_the_account(answers: dict[str, Any]) -> None:
    """An unlock has no undo, so an armed unlock writes nothing back."""
    answer = answers["armed-unlock-then-change"]
    assert _current_record(answer)["state"] == "armed"
    assert answer["results"][1]["response"]["code"] == "ok", answer["results"][1]


def test_an_apply_whose_store_cannot_be_checked_for_an_armed_record_is_an_error(
    answers: dict[str, Any],
) -> None:
    """A record that cannot be read may be an armed record of the target."""
    answer = answers["armed-unreadable-then-change"]
    assert answer["code"] == "error", answer
    assert _ldap_modifies(answer) == 0


# ---- the apply's own cleanup of a new user deletes only by its GUID ----------


def test_a_cleanup_with_no_guid_never_deletes_the_account_at_the_planned_dn(
    answers: dict[str, Any],
) -> None:
    """No GUID was read: an account at the planned DN may not be Newton's
    (here it is somebody else's, and Newton's was moved away), so nothing is
    deleted.  The record is undo_failed with the DN, never undone."""
    answer = answers["user-create-moved-replaced-no-guid"]
    assert answer["code"] == "error"
    assert _object_with_dn(answer, NEW_USER_DN)["guid"] == REPLACEMENT_GUID
    _object_with_dn(answer, MOVED_NEW_USER_DN)
    assert not [call for call in _calls(answer) if call.startswith("ldap:delete")]
    record = _current_record(answer)
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [NEW_USER_DN]


def test_a_cleanup_with_a_guid_deletes_only_the_object_of_that_guid(
    answers: dict[str, Any],
) -> None:
    """The GUID of Newton's new user was read and its uSNChanged was not: the
    cleanup deletes the object of that GUID wherever it is, and keeps the
    replacement at the planned DN.  The record is undone."""
    answer = answers["user-create-moved-replaced-guid"]
    assert answer["code"] == "error"
    assert _object_with_dn(answer, NEW_USER_DN)["guid"] == REPLACEMENT_GUID
    with pytest.raises(AssertionError):
        _object_with_dn(answer, MOVED_NEW_USER_DN)
    record = _current_record(answer)
    assert record["state"] == "undone"
    assert record["restored"] is True


def test_a_cleanup_by_guid_whose_delete_answer_was_lost_reads_the_guid_again(
    answers: dict[str, Any],
) -> None:
    """The delete by GUID landed and its answer was lost: the object of the
    GUID is gone, so the record is undone; the replacement is kept."""
    answer = answers["user-create-moved-replaced-guid-delete-lost"]
    assert answer["code"] == "error"
    assert _object_with_dn(answer, NEW_USER_DN)["guid"] == REPLACEMENT_GUID
    with pytest.raises(AssertionError):
        _object_with_dn(answer, MOVED_NEW_USER_DN)
    assert _current_record(answer)["state"] == "undone"


# ---- every write acts on the object of its GUID, in the one request ---------
#
# Each write names its object by the GUID form of a DN, never by a DN a
# search answered earlier: somebody may move Newton's object away and create
# another at that DN between the search and the write.  The fake's hook runs
# inside the write, before the fake finds the object.


def _guid_of(answer: dict[str, Any], dn: str) -> str:
    return str(_object_with_dn(answer, dn)["guid"])


def _gone(answer: dict[str, Any], dn: str) -> bool:
    return not any(str(entry["dn"]) == dn for entry in answer["objects"])


def _values(answer: dict[str, Any], dn: str, name: str) -> list[str]:
    return [str(one) for one in (_object_with_dn(answer, dn)["values"].get(name) or [])]


@pytest.mark.parametrize("refused", [False, True])
def test_a_cleanup_by_guid_never_deletes_an_account_made_at_the_dn_during_the_delete(
    answers: dict[str, Any], refused: bool
) -> None:
    """The GUID of Newton's new user was read and its uSNChanged was not;
    between the cleanup's lookup and its delete somebody moves Newton's
    object away and creates another account at the planned DN.  The delete
    names the GUID: Newton's object is deleted wherever it is and the
    replacement is kept (a delete the server refuses leaves both, and the
    record is undo_failed), never undone with the replacement gone."""
    answer = answers["cleanup-replaced-during-delete" + ("-refused" if refused else "")]
    assert answer["code"] == "error"
    assert [call for call in _calls(answer) if call.startswith("ldap:delete")]
    assert not _gone(answer, NEW_USER_DN), "the replacement was deleted"
    assert _guid_of(answer, NEW_USER_DN) == REPLACEMENT_GUID
    record = _current_record(answer)
    if refused:
        assert not _gone(answer, MOVED_NEW_USER_DN)
        assert record["state"] == "undo_failed"
        assert record["restored"] is False
    else:
        assert _gone(answer, MOVED_NEW_USER_DN)
        assert record["state"] == "undone"
        assert record["restored"] is True


@pytest.mark.parametrize("way", ["abort", "task"])
def test_the_undo_of_a_user_create_never_deletes_an_account_made_at_the_dn_during_the_delete(
    answers: dict[str, Any], way: str
) -> None:
    answer = answers["user-create-undo-replaced-during-delete-" + way]
    assert answer["results"][0]["code"] == "ok"
    assert not _gone(answer, NEW_USER_DN), "the replacement was deleted"
    assert _guid_of(answer, NEW_USER_DN) == REPLACEMENT_GUID
    assert _gone(answer, MOVED_NEW_USER_DN)
    record = _current_record(answer)
    assert record["state"] == "undone"
    assert record["restored"] is True


def test_the_undo_of_a_user_create_whose_guid_delete_is_refused_keeps_both_accounts(
    answers: dict[str, Any],
) -> None:
    answer = answers["user-create-undo-replaced-during-delete-refused"]
    assert _guid_of(answer, NEW_USER_DN) == REPLACEMENT_GUID
    assert not _gone(answer, MOVED_NEW_USER_DN)
    assert _current_record(answer)["state"] == "undo_failed"


def test_an_apply_modify_never_writes_an_account_made_at_the_dn_during_the_write(
    answers: dict[str, Any],
) -> None:
    answer = answers["uac-apply-replaced-during-modify"]
    assert answer["code"] == "ok", answer["response"]
    assert _guid_of(answer, MOVED_SEED_DN) == SEED_GUID
    assert _values(answer, MOVED_SEED_DN, "useraccountcontrol") == ["66048"]
    assert _guid_of(answer, SEED_DN) == REPLACEMENT_GUID
    assert _values(answer, SEED_DN, "useraccountcontrol") == ["4260352"]


@pytest.mark.parametrize("way", ["abort", "task"])
def test_an_undo_modify_never_writes_an_account_made_at_the_dn_during_the_write(
    answers: dict[str, Any], way: str
) -> None:
    answer = answers["uac-undo-replaced-during-modify-" + way]
    assert answer["results"][0]["code"] == "ok"
    assert _values(answer, MOVED_SEED_DN, "useraccountcontrol") == ["4260352"]
    assert _guid_of(answer, SEED_DN) == REPLACEMENT_GUID
    assert _values(answer, SEED_DN, "useraccountcontrol") == ["66048"]
    assert _current_record(answer)["state"] == "undone"


def test_a_member_add_never_writes_a_group_made_at_the_dn_during_the_write(
    answers: dict[str, Any],
) -> None:
    answer = answers["member-apply-replaced-during-modify"]
    assert answer["code"] == "ok", answer["response"]
    assert _values(answer, MOVED_GROUP_DN, "member") == [MEMBER_DN]
    assert _guid_of(answer, GROUP_DN) == REPLACEMENT_GUID
    assert _values(answer, GROUP_DN, "member") == []


def test_the_undo_of_a_member_add_never_writes_a_group_made_at_the_dn_during_the_write(
    answers: dict[str, Any],
) -> None:
    answer = answers["member-undo-replaced-during-modify"]
    assert answer["results"][0]["code"] == "ok"
    assert _values(answer, MOVED_GROUP_DN, "member") == []
    assert _guid_of(answer, GROUP_DN) == REPLACEMENT_GUID
    assert _values(answer, GROUP_DN, "member") == [MEMBER_DN]
    assert _current_record(answer)["state"] == "undone"


def test_a_move_never_renames_an_account_made_at_the_dn_during_the_rename(
    answers: dict[str, Any],
) -> None:
    answer = answers["move-apply-replaced-during-modifydn"]
    assert answer["code"] == "ok", answer["response"]
    assert _guid_of(answer, SEED_OPS_DN) == SEED_GUID
    assert _guid_of(answer, SEED_DN) == REPLACEMENT_GUID
    assert _gone(answer, MOVED_SEED_DN)


def test_the_undo_of_a_move_never_renames_an_account_made_at_the_dn_during_the_rename(
    answers: dict[str, Any],
) -> None:
    answer = answers["move-undo-replaced-during-modifydn"]
    assert answer["results"][0]["code"] == "ok"
    assert _guid_of(answer, SEED_DN) == SEED_GUID
    assert _guid_of(answer, SEED_OPS_DN) == REPLACEMENT_GUID
    assert _gone(answer, MOVED_SEED_DN)
    assert _current_record(answer)["state"] == "undone"


def test_every_write_of_the_helper_names_its_object_by_guid(answers: dict[str, Any]) -> None:
    """Every delete, modify and rename these cases sent (a user-create's
    cleanup and undo, an attribute verb, a membership and a move, and their
    undos) named its object by the GUID form of the DN."""
    names = []
    for case, answer in answers.items():
        if "replaced-during" not in case:
            continue
        for line in answer["log"]:
            kind, _, rest = str(line).partition(" ")
            if kind in ("delete", "modify", "modifydn"):
                names.append((case, kind, rest.split(" ")[0] if kind != "modify" else rest))
    assert {kind for _, kind, _ in names} == {"delete", "modify", "modifydn"}
    assert all(name.startswith("<GUID=") for _, _, name in names), names


# ---- an attribute the bind cannot read is never read as a known value --------
#
# The helper binds as the DC's account, so the directory's ACLs apply: an
# attribute it has no read right on is left out of the answer and a filter
# on it behaves as if the object did not hold it (MS-ADTS 3.1.1.4.3).  An
# empty group and a group whose member the bind cannot read look the same,
# and so do a missing value and an unreadable one.  The fake's
# hidden_attributes and hide_on_modify knobs and the harness's
# hide_attributes change model that; a write still sees the values.

UNDO_WAYS = (
    ("abort", {"raw": _mode("abort"), "stage": "write"}),
    ("task", {"stage": "undo", "undo": TXID}),
    ("sweep", {"raw": _read(), "stage": "write", "now": NOW + 601}),
)


def _group(**fields: Any) -> dict[str, Any]:
    return _object(GROUP_DN, GROUP_GUID, GROUP_SID, GROUP_SAM,
                   object_class=["top", "group"], parent=OU_USERS, **fields)


def _member() -> dict[str, Any]:
    return _object(MEMBER_DN, MEMBER_GUID, MEMBER_SID, MEMBER_SAM, parent=OU_USERS)


def _member_remove() -> str:
    return _apply(
        "member-remove",
        target={
            "group_guid": GROUP_GUID, "group_sid": GROUP_SID, "group_sam": GROUP_SAM,
            "member_guid": MEMBER_GUID, "member_sid": MEMBER_SID, "member_sam": MEMBER_SAM,
        },
        before={"member": "present"},
        after={"member": "absent"},
    )


HIDE_MEMBER = {"stage": "directory", "hide_attributes": ["member"]}


def _unreadable_cases(add: Any) -> None:
    add("hidden-member-add-apply",
        ldap=_directory(objects=[_group(), _member()], hidden_attributes=["member"]),
        requests=[{"raw": _member_add(), "stage": "write"}])
    add("hidden-member-add-already-in",
        ldap=_directory(objects=[_group(member=[MEMBER_DN]), _member()],
                        hidden_attributes=["member"]),
        requests=[{"raw": _member_add(), "stage": "write"}])
    add("hidden-member-remove-apply",
        ldap=_directory(objects=[_group(member=[MEMBER_DN]), _member()],
                        hidden_attributes=["member"]),
        requests=[{"raw": _member_remove(), "stage": "write"}])
    add("hidden-member-add-confirm",
        ldap=_directory(objects=[_group(), _member()]),
        requests=[{"raw": _member_add(), "stage": "write"}, HIDE_MEMBER,
                  {"raw": _mode("confirm"), "stage": "write"}])
    for way, request in UNDO_WAYS:
        for lost in (False, True):
            suffix = way + ("-lost" if lost else "")
            extra: dict[str, Any] = {"no_response_on_modify": 2} if lost else {}
            add("hidden-member-add-undo-" + suffix,
                ldap=_directory(objects=[_group(**extra), _member()]),
                requests=[{"raw": _member_add(), "stage": "write"}, HIDE_MEMBER, request])
            add("hidden-member-remove-undo-" + suffix,
                ldap=_directory(objects=[_group(member=[MEMBER_DN], **extra), _member()]),
                requests=[{"raw": _member_remove(), "stage": "write"}, HIDE_MEMBER, request])
            add("hidden-etypes-undo-" + suffix,
                ldap=_directory(objects=[_seed(etypes=None, **extra)]),
                requests=[{"raw": _etypes_apply(), "stage": "write"},
                          {"stage": "directory",
                           "hide_attributes": ["msDS-SupportedEncryptionTypes"]},
                          request])
    add("hidden-maq-confirm", ldap=_directory(),
        requests=[{"raw": _maq_apply(), "stage": "write"},
                  {"stage": "directory",
                   "set_values": {"dn": DOMAIN_DN, "name": "ms-DS-MachineAccountQuota",
                                  "values": ["10"]}},
                  {"stage": "directory", "hide_attributes": ["ms-DS-MachineAccountQuota"]},
                  {"raw": _mode("confirm"), "stage": "write"}])
    for way, request in UNDO_WAYS:
        # the undo reads the member present (one search), its remove gets no
        # answer and does not land, and its re-read meets the flipping right
        for name, flags in (("once", [True, False, True]),
                            ("twice", [True, False, True, False, False])):
            add("flip-member-add-undo-%s-%s" % (name, way),
                ldap=_directory(objects=[_group(no_response_on_modify=2), _member()]),
                requests=[{"raw": _member_add(), "stage": "write"},
                          {"stage": "directory", "member_readable_by_search": flags},
                          request])
    add("flip-member-absent-control",
        ldap=_directory(objects=[_group(member=[SEED_DN]), _member()]),
        requests=[{"stage": "directory", "member_readable_by_search": [True, True, True, True]},
                  {"raw": _read("member-add", MEMBER_READ_TARGET), "stage": "write"}])
    hide_new_guid = {"stage": "directory",
                     "hide_attributes_of": {"sam": "new.user", "names": ["objectGUID"]}}
    hide_new_entry = {"stage": "directory",
                      "hide_attributes_of": {"sam": "new.user",
                                             "names": ["objectGUID", "objectClass"]}}
    for way, request in UNDO_WAYS:
        add("hidden-guid-user-create-undo-" + way, ldap=_directory(),
            requests=[{"raw": _user_create_apply(), "stage": "write"}, hide_new_guid, request])
        add("hidden-guid-user-create-undo-refused-" + way, ldap=_directory(ldap_delete_error=52),
            requests=[{"raw": _user_create_apply(), "stage": "write"}, hide_new_guid, request])
        add("hidden-entry-user-create-undo-" + way, ldap=_directory(),
            requests=[{"raw": _user_create_apply(), "stage": "write"}, hide_new_entry, request])
    for names in (["objectGUID"], ["objectGUID", "objectClass"]):
        add("hidden-guid-user-create-cleanup-" + "-".join(names),
            ldap=_directory(created_missing_usn=True, ldap_delete_error=52,
                            hide_on_delete=names),
            requests=[{"raw": _user_create_apply(), "stage": "write"}])
    add("hidden-unlock-lost-answer",
        ldap=_directory(objects=[_seed(lockout=1000, modify_error_no_response=1)],
                        hide_on_modify=["lockoutTime"]),
        requests=[{"raw": _unlock_apply(), "stage": "write"}])


def _etypes_apply() -> str:
    return _apply(
        "enc-types",
        target={"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM},
        before={"etypes": "absent"},
        after={"etypes": 24},
    )


def _maq_apply() -> str:
    return _apply("maq", target={"guid": PARENT_GUID}, before={"maq": 10}, after={"maq": 0})


def _members_of(answer: dict[str, Any]) -> list[str]:
    return list(_object_with_dn(answer, GROUP_DN)["values"].get("member", []))


def test_a_member_add_read_back_with_the_member_unreadable_is_unreadable(
    answers: dict[str, Any],
) -> None:
    """The add landed and the group's member cannot be read: the answer's
    live value is a target that cannot be read, never "absent"."""
    answer = answers["hidden-member-add-apply"]
    response = answer["results"][0]["response"]
    assert response["code"] == "ok", response
    assert response["live"] == {}
    assert _members_of(answer) == [MEMBER_DN]


def test_a_member_add_with_the_member_unreadable_and_already_in_writes_nothing(
    answers: dict[str, Any],
) -> None:
    answer = answers["hidden-member-add-already-in"]
    assert _codes(answer)[0] == "conflict", answer["results"][0]
    assert _members_of(answer) == [MEMBER_DN]
    assert _current_record(answer)["state"] == "refused"


def test_a_member_remove_with_the_member_unreadable_is_refused(answers: dict[str, Any]) -> None:
    """A member the bind cannot read is never taken for present: the
    before-check refuses, nothing is written."""
    answer = answers["hidden-member-remove-apply"]
    assert _codes(answer)[0] == "conflict", answer["results"][0]
    assert _members_of(answer) == [MEMBER_DN]
    assert _ldap_modifies(answer) == 0


def test_a_member_add_confirm_with_the_member_unreadable_is_refused(
    answers: dict[str, Any],
) -> None:
    answer = answers["hidden-member-add-confirm"]
    assert _codes(answer)[2] == "conflict", answer["results"][2]
    assert _current_record(answer)["state"] == "armed"


@pytest.mark.parametrize("lost", [False, True])
@pytest.mark.parametrize("way", [one for one, _ in UNDO_WAYS])
def test_a_member_add_undo_with_the_member_unreadable_never_says_undone_with_the_member_in(
    answers: dict[str, Any], way: str, lost: bool
) -> None:
    """Newton's member-add landed, then the group's member became unreadable.
    The undo's remove lands (undone, the member out) or gets no answer: the
    re-read cannot tell, so the record stays armed with its task."""
    answer = answers["hidden-member-add-undo-" + way + ("-lost" if lost else "")]
    record = _current_record(answer)
    if lost:
        assert _members_of(answer) == [MEMBER_DN]
        assert record["state"] == "armed"
        assert record["restored"] is False
    else:
        assert _members_of(answer) == []
        assert record["state"] == "undone"
        assert record["restored"] is True


@pytest.mark.parametrize("lost", [False, True])
@pytest.mark.parametrize("way", [one for one, _ in UNDO_WAYS])
def test_a_member_remove_undo_with_the_member_unreadable_writes_the_member_back(
    answers: dict[str, Any], way: str, lost: bool
) -> None:
    answer = answers["hidden-member-remove-undo-" + way + ("-lost" if lost else "")]
    record = _current_record(answer)
    if lost:
        assert _members_of(answer) == []
        assert record["state"] == "armed"
        assert record["restored"] is False
    else:
        assert _members_of(answer) == [MEMBER_DN]
        assert record["state"] == "undone"
        assert record["restored"] is True


@pytest.mark.parametrize("lost", [False, True])
@pytest.mark.parametrize("way", [one for one, _ in UNDO_WAYS])
def test_an_enc_types_undo_with_the_value_unreadable_never_says_undone_with_it_there(
    answers: dict[str, Any], way: str, lost: bool
) -> None:
    """Newton's enc-types put a value where there was none, then the value
    became unreadable: with a lost answer the re-read cannot tell "no
    value" from "a value the bind cannot read", so the record stays armed."""
    answer = answers["hidden-etypes-undo-" + way + ("-lost" if lost else "")]
    values = _object_of(answer, SEED_SAM)["values"].get("msds-supportedencryptiontypes")
    record = _current_record(answer)
    if lost:
        assert values == ["24"]
        assert record["state"] == "armed"
        assert record["restored"] is False
    else:
        assert not values
        assert record["state"] == "undone"
        assert record["restored"] is True


def test_a_maq_confirm_with_the_quota_unreadable_is_refused(answers: dict[str, Any]) -> None:
    """Newton set the quota to 0, somebody set it back to 10 and the quota
    became unreadable: "no value" is never the after-image 0."""
    answer = answers["hidden-maq-confirm"]
    assert _codes(answer)[0] == "ok", answer["results"][0]
    assert _codes(answer)[3] == "conflict", answer["results"][3]
    assert _current_record(answer)["state"] == "armed"


def test_an_unlock_whose_answer_was_lost_and_lockout_cannot_be_read_stays_armed(
    answers: dict[str, Any],
) -> None:
    """The unlock got no answer and did not land, and the lockoutTime became
    unreadable during the write: "no value" is never the after-image 0, so
    the unlock is never recorded confirmed."""
    answer = answers["hidden-unlock-lost-answer"]
    assert _codes(answer)[0] == "error", answer["results"][0]
    assert _object_of(answer, SEED_SAM)["values"]["lockouttime"] == ["1000"]
    assert _current_record(answer)["state"] == "armed"


# ---- the verification read of every DC is an outcome read ---------------------
#
# Newton reads the target back from every DC (read mode) and confirms only
# when every one shows the after-image.  Each DC binds as its own account,
# so a replica may hold another value it cannot read: the read answers
# ``outcome`` (Get-NewtonReadLive), and Newton matches that, never the
# planning image ``live``.

SEED_READ_TARGET = {"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM}
MEMBER_READ_TARGET = {
    "group_guid": GROUP_GUID, "group_sid": GROUP_SID, "group_sam": GROUP_SAM,
    "member_guid": MEMBER_GUID, "member_sid": MEMBER_SID, "member_sam": MEMBER_SAM,
}
REPLICA_READS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "maq": ({"verb": "maq", "target": {"guid": PARENT_GUID}}, {"maq": 0}),
    "unlock": ({"verb": "unlock", "target": SEED_READ_TARGET}, {"lockout": 0}),
    "enc-types": ({"verb": "enc-types", "target": SEED_READ_TARGET}, {"etypes": 24}),
    "member-add": ({"verb": "member-add", "target": MEMBER_READ_TARGET}, {"member": "present"}),
}


def _quota(value: str) -> dict[str, Any]:
    return {"stage": "directory",
            "set_values": {"dn": DOMAIN_DN, "name": "ms-DS-MachineAccountQuota",
                           "values": [value]}}


def _replica_read(case: str) -> dict[str, Any]:
    fields = REPLICA_READS[case][0]
    return {"raw": json.dumps({"v": 1, "mode": "read", "device": DEVICE, **fields}),
            "stage": "write"}


def _replica_cases(add: Any) -> None:
    hidden = {"maq": "ms-DS-MachineAccountQuota", "unlock": "lockoutTime",
              "enc-types": "msDS-SupportedEncryptionTypes", "member-add": "member"}
    held = {  # the before value the replica still holds, and the after-image
        "unlock": ([_seed(lockout=1000)], [_seed(lockout=0)]),
        "enc-types": ([_seed(etypes=16)], [_seed(etypes=24)]),
        "member-add": ([_group(), _member()], [_group(member=[MEMBER_DN]), _member()]),
    }
    for case in REPLICA_READS:
        hide = {"stage": "directory", "hide_attributes": [hidden[case]]}
        if case == "maq":
            add("replica-hidden-maq", ldap=_directory(),
                requests=[_quota("10"), hide, _replica_read(case)])
            add("replica-shown-maq", ldap=_directory(),
                requests=[_quota("0"), _replica_read(case)])
            continue
        before, after = held[case]
        add("replica-hidden-" + case, ldap=_directory(objects=before),
            requests=[hide, _replica_read(case)])
        add("replica-shown-" + case, ldap=_directory(objects=after),
            requests=[_replica_read(case)])
    add("replica-etypes-none", ldap=_directory(objects=[_seed(etypes=None)]),
        requests=[_replica_read("enc-types")])
    add("replica-hidden-move-parent", ldap=_directory(),
        requests=[{"stage": "directory",
                   "hide_attributes_of": {"dn": OU_USERS, "names": ["objectGUID", "objectClass"]}},
                  {"raw": _read("move", SEED_READ_TARGET), "stage": "write"}])
    add("replica-hidden-uac", ldap=_directory(),
        requests=[{"stage": "directory", "hide_attributes": ["userAccountControl"]},
                  {"raw": _read("uac-clear", {**SEED_READ_TARGET, "bit": 4194304}),
                   "stage": "write"}])


def _verified(response: dict[str, Any], fields: dict[str, Any],
              after: dict[str, Any]) -> dict[str, Any]:
    """Newton's verification of one DC (apply._verify) answered with the
    helper's read answer."""
    plan = {"device": DEVICE, "after": after, **fields}
    replica = type("Device", (), {"name": "windc2"})()
    return core_apply._verify(
        lambda device, payload: response, [replica], plan, 0, 0,
        lambda seconds: None, lambda: 0.0,
    )["windc2"]


def _read_response(answer: dict[str, Any]) -> dict[str, Any]:
    response = answer["results"][-1]["response"]
    assert response["code"] == "ok", answer["results"][-1]
    return response


@pytest.mark.parametrize("case", list(REPLICA_READS))
def test_a_replica_whose_value_cannot_be_read_never_verifies_matched(
    answers: dict[str, Any], case: str
) -> None:
    """The replica still holds the before value and its bind cannot read
    it: the read answers an outcome that is not the after-image, so the DC
    never reads matched and the change is never confirmed."""
    fields, after = REPLICA_READS[case]
    response = _read_response(answers["replica-hidden-" + case])
    assert response["outcome"] != after
    if case in ("maq", "unlock"):
        assert response["outcome"] == {}
    state = _verified(response, fields, after)
    assert state["state"] == "not_tested"
    assert state["live"] != after


@pytest.mark.parametrize("case", list(REPLICA_READS))
def test_a_replica_that_shows_the_after_image_verifies_matched(
    answers: dict[str, Any], case: str
) -> None:
    fields, after = REPLICA_READS[case]
    response = _read_response(answers["replica-shown-" + case])
    assert response["outcome"] == after
    assert _verified(response, fields, after) == {"state": "matched", "live": after}


def test_a_read_of_a_user_account_control_the_bind_cannot_read_has_an_empty_outcome(
    answers: dict[str, Any],
) -> None:
    """Every account carries a userAccountControl, so no value is one the
    bind cannot read: the planning image reads 0, the outcome is empty (and
    Newton refuses to plan on it)."""
    response = _read_response(answers["replica-hidden-uac"])
    assert response["live"] == {"uac": 0}
    assert response["outcome"] == {}


def test_a_read_of_a_move_parent_the_bind_cannot_read_has_an_empty_outcome(
    answers: dict[str, Any],
) -> None:
    """The account's parent cannot be read: the planning image names no
    parent and the outcome is empty, so Newton refuses to plan on it."""
    response = _read_response(answers["replica-hidden-move-parent"])
    assert response["live"] == {"parent": ""}
    assert response["outcome"] == {}


def test_a_replica_read_of_an_enc_types_removal_takes_no_value_for_the_removal(
    answers: dict[str, Any],
) -> None:
    """No value is the after-image of an enc-types that removes the value
    (the read-back's known limit), and never a number."""
    fields = REPLICA_READS["enc-types"][0]
    response = _read_response(answers["replica-etypes-none"])
    assert response["outcome"] == {"etypes": "absent"}
    assert _verified(response, fields, {"etypes": "absent"})["state"] == "matched"
    assert _verified(response, fields, {"etypes": 24})["state"] == "not_tested"


# ---- membership is decided across searches the bind's rights may change between --
#
# Get-NewtonMembership decides with separate base searches of the group.  An
# ACL that makes member unreadable for (member=<GUID=m>) and readable again
# for (member=*) would read "absent" while the member is in.  After
# (member=*) matches, (member=<GUID=m>) and then (member=*) run again:
# absent only when the first still misses and the second still matches,
# else empty.  The fake's member_readable_by_search knob changes the right
# between searches.


@pytest.mark.parametrize("flips", ["once", "twice"])
@pytest.mark.parametrize("way", [way for way, _ in UNDO_WAYS])
def test_a_member_add_undo_whose_member_right_flips_between_searches_never_says_undone_with_it_in(
    answers: dict[str, Any], way: str, flips: str
) -> None:
    """Newton's member-add landed; the undo's remove got no answer and did
    not land.  During its re-read the bind cannot read member for the
    equality search and can for (member=*) (and, twice, cannot again).
    Reading "absent" from that would record undone, restored, with the
    member in.  The outcome is unknown: the record stays armed."""
    answer = answers["flip-member-add-undo-%s-%s" % (flips, way)]
    record = _current_record(answer)
    assert MEMBER_DN in _members_of(answer)
    assert record["state"] == "armed"
    assert record["restored"] is False


def test_a_member_that_is_out_still_reads_absent_after_the_second_check(
    answers: dict[str, Any],
) -> None:
    """The control: the group holds another member the bind can read and
    not this one, so both checks agree and the membership reads absent."""
    response = answers["flip-member-absent-control"]["results"][-1]["response"]
    assert response["code"] == "ok", response
    assert response["live"] == {"member": "absent"}
    assert response["outcome"] == {"member": "absent"}


# ---- a new user is proven gone only by a read that says so ------------------
#
# A filter on an objectGUID the bind cannot read matches nothing (MS-ADTS
# 3.1.1.4.3), so a subtree search by the GUID that finds nothing is no proof
# the user is gone.  The proof is a base search of <GUID=...> (MS-ADTS
# 3.1.1.3.1.2.4) that answers noSuchObject (RFC 4511 4.5.1.1: a base object
# that does not exist).


def _new_user_there(answer: dict[str, Any]) -> bool:
    return any(str(entry["dn"]) == NEW_USER_DN for entry in answer["objects"])


@pytest.mark.parametrize("way", [way for way, _ in UNDO_WAYS])
def test_a_user_create_undo_with_the_guid_unreadable_never_says_undone_with_the_user_there(
    answers: dict[str, Any], way: str
) -> None:
    """Newton's new user is there and its objectGUID became unreadable to
    the bind.  An undo that took the empty GUID search for "gone" would
    record undone with the user there.  The undo reads it by its GUID name
    and deletes it."""
    answer = answers["hidden-guid-user-create-undo-" + way]
    record = _current_record(answer)
    assert not _new_user_there(answer)
    assert record["state"] == "undone"
    assert record["restored"] is True


@pytest.mark.parametrize("way", [way for way, _ in UNDO_WAYS])
def test_a_user_create_undo_whose_delete_is_refused_with_the_guid_unreadable_is_undo_failed(
    answers: dict[str, Any], way: str
) -> None:
    """The server refuses the undo's delete and the objectGUID cannot be
    read: the user is there, so the record is undo_failed with its GUID,
    never undone."""
    answer = answers["hidden-guid-user-create-undo-refused-" + way]
    record = _current_record(answer)
    assert _new_user_there(answer)
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [str(record["created"]["guid"])]


@pytest.mark.parametrize("way", [way for way, _ in UNDO_WAYS])
def test_a_user_create_undo_whose_user_answers_nothing_is_never_undone(
    answers: dict[str, Any], way: str
) -> None:
    """The base search of the user's GUID name answers no entry and no
    error: the user is there and the bind cannot read it.  It is never
    deleted unread and never taken for gone."""
    answer = answers["hidden-entry-user-create-undo-" + way]
    record = _current_record(answer)
    assert _new_user_there(answer)
    assert not any(call.startswith("ldap:delete") for call in _calls(answer))
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert record["conflicts"] == [str(record["created"]["guid"])]


@pytest.mark.parametrize("names", ["objectGUID", "objectGUID-objectClass"])
def test_a_user_create_cleanup_whose_refused_delete_meets_an_unreadable_guid_is_never_undone(
    answers: dict[str, Any], names: str
) -> None:
    """The uSNChanged of the new user is missing, so the apply deletes it at
    once by its GUID; the server refuses the delete and the objectGUID then
    cannot be read.  The user is there: the record is never undone."""
    answer = answers["hidden-guid-user-create-cleanup-" + names]
    assert _new_user_there(answer)
    record = _current_record(answer)
    assert record["state"] == "undo_failed"
    assert record["restored"] is False
    assert len(record["conflicts"]) == 1


# ---- the same-target guard holds for every verb with an undo ---------------

SEED_TARGET = {"guid": SEED_GUID, "sid": SEED_SID, "sam": SEED_SAM}
OTHER_TARGET = {"guid": MEMBER_GUID, "sid": MEMBER_SID, "sam": MEMBER_SAM}


def _membership_target(guid: str, sid: str, sam: str) -> dict[str, Any]:
    return {"group_guid": GROUP_GUID, "group_sid": GROUP_SID, "group_sam": GROUP_SAM,
            "member_guid": guid, "member_sid": sid, "member_sam": sam}


def _same_target_requests(verb: str) -> tuple[dict[str, Any], dict[str, Any] | None, list[Any]]:
    """The apply fields of one verb on a target, the same verb on another
    target (None for the domain's quota, which has one target only) and the
    objects of the directory."""
    seed: dict[str, Any] = {}
    other: dict[str, Any] = {}
    group: dict[str, Any] = {}
    if verb in ("uac-clear", "disable", "enable"):
        before, after = {"uac-clear": (4260352, 66048), "disable": (66048, 66050),
                         "enable": (66050, 66048)}[verb]
        seed["uac"] = other["uac"] = before
        bit = {"bit": 4194304} if verb == "uac-clear" else {}
        shape: dict[str, Any] = {"verb": verb, "before": {"uac": before}, "after": {"uac": after}}
        first = {**shape, "target": {**SEED_TARGET, **bit}}
        second: dict[str, Any] | None = {**shape, "target": {**OTHER_TARGET, **bit}}
    elif verb == "enc-types":
        shape = {"verb": verb, "before": {"etypes": 0}, "after": {"etypes": 24}}
        first, second = {**shape, "target": SEED_TARGET}, {**shape, "target": OTHER_TARGET}
    elif verb == "move":
        shape = {"verb": verb, "before": {"parent": OU_GUID}, "after": {"parent": OU_OPS_GUID}}
        first, second = {**shape, "target": SEED_TARGET}, {**shape, "target": OTHER_TARGET}
    elif verb == "maq":
        first = {"verb": verb, "target": {"guid": PARENT_GUID},
                 "before": {"maq": 10}, "after": {"maq": 20}}
        second = None
    elif verb in ("member-add", "member-remove"):
        if verb == "member-add":
            shape = {"verb": verb, "before": {"member": "absent"}, "after": {"member": "present"}}
        else:
            group["member"] = [MEMBER_DN, SEED_DN]
            shape = {"verb": verb, "before": {"member": "present"}, "after": {"member": "absent"}}
        first = {**shape, "target": _membership_target(MEMBER_GUID, MEMBER_SID, MEMBER_SAM)}
        second = {**shape, "target": _membership_target(SEED_GUID, SEED_SID, SEED_SAM)}
    elif verb == "user-create":
        shape = dict(verb=verb, before={"object": "absent"}, after={"object": "present"},
                     secret="a-very-secret-password")
        first = {**shape, "target": {"parent_guid": PARENT_GUID, "sam": "new.user"}}
        second = {**shape, "target": {"parent_guid": PARENT_GUID, "sam": "new.user2"}}
    else:
        raise AssertionError(verb)
    objects = [_seed(**seed), _group(**group),
               _object(MEMBER_DN, MEMBER_GUID, MEMBER_SID, MEMBER_SAM, parent=OU_USERS, **other),
               _object(OU_USERS, OU_GUID, object_class=["top", "organizationalUnit"]),
               _object(OU_OPS, OU_OPS_GUID, object_class=["top", "organizationalUnit"])]
    return first, second, objects


def _armed_record_of(txid: str, fields: dict[str, Any]) -> str:
    payload = json.loads(_apply(txid=txid, **fields))
    payload.pop("token", None)
    payload.pop("secret", None)
    return json.dumps({
        "v": 1, "txid": txid, "request": payload, "created": None,
        "state": "armed", "undo_at": NOW + 600, "restored": False, "conflicts": [],
    })


WIN_GUARDED_VERBS = [
    "uac-clear", "disable", "enable", "enc-types", "move", "maq",
    "member-add", "member-remove", "user-create",
]


def _same_target_cases(add: Any) -> None:
    for verb in WIN_GUARDED_VERBS:
        first, second, objects = _same_target_requests(verb)
        store = {TXID_C + ".0.json": _armed_record_of(TXID_C, first)}
        add("same-target-" + verb, ldap=_directory(objects=objects), store_files=store,
            requests=[{"raw": _apply(txid=TXID_B, **first), "stage": "write"}])
        if second is not None:
            add("other-target-" + verb, ldap=_directory(objects=objects), store_files=store,
                requests=[{"raw": _apply(txid=TXID_B, **second), "stage": "write"}])


def _ldap_writes(answer: dict[str, Any]) -> list[str]:
    return [call for call in _calls(answer)
            if call.split(" ")[0] in ("ldap:modify", "ldap:add", "ldap:modifydn", "ldap:delete")]


@pytest.mark.parametrize("verb", WIN_GUARDED_VERBS)
def test_an_apply_of_a_target_another_armed_record_of_the_verb_names_is_refused(
    answers: dict[str, Any], verb: str
) -> None:
    """A is armed (its undo_at is ahead); B, the same verb on the same target,
    is refused with conflict and armed true before anything is armed or
    written, and B's record is refused."""
    answer = answers["same-target-" + verb]
    response = answer["results"][0]["response"]
    assert response["code"] == "conflict", response
    assert response["armed"] is True
    assert _ldap_writes(answer) == []
    assert "task:register newton-undo-" + TXID_B not in _calls(answer)
    assert _record_of(answer, TXID_B)["state"] == "refused"
    assert _record_of(answer, TXID_C)["state"] == "armed"


@pytest.mark.parametrize("verb", [one for one in WIN_GUARDED_VERBS if one != "maq"])
def test_an_apply_of_another_target_of_the_same_verb_goes_through(
    answers: dict[str, Any], verb: str
) -> None:
    answer = answers["other-target-" + verb]
    assert answer["results"][0]["response"]["code"] == "ok", answer["results"][0]
    assert _record_of(answer, TXID_C)["state"] == "armed"
