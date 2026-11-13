"""The AD write request contract (SPEC-1.4-REQUEST sections 2 to 4).

Every rule of the schema is a refusal with the code ``schema`` and every
rule of the verb table is a refusal with the code the request deserves.
The rules are checked before anything else happens, so a request that
does not fit the contract never reaches a device.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from newton_mcp.ad.write import request


BASE: dict[str, Any] = {
    "v": 1,
    "mode": "apply",
    "device": "lab-win",
    "txid": "0123456789abcdef0123456789abcdef",
    "verb": "uac-clear",
    "target": {
        "guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
        "sid": "S-1-5-21-1-2-3-1105",
        "sam": "seed-asrep",
        "bit": 4194304,
    },
    "before": {"uac": 4260352},
    "after": {"uac": 66048},
    "window": 600,
    "risk": "MED",
    "nbf": 1800000000,
    "exp": 1800000600,
    "token": "a" * 64,
}

ACCOUNT_TARGET = {
    "guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
    "sid": "S-1-5-21-1-2-3-1105",
    "sam": "seed-asrep",
}


def body(**changes: Any) -> dict[str, Any]:
    """A fresh copy of the good request with changes applied."""
    out = copy.deepcopy(BASE)
    out.update(changes)
    return out


def raw(**changes: Any) -> bytes:
    """The good request as bytes."""
    return json.dumps(body(**changes)).encode("utf-8")


def raw_number(field: str, text: str) -> bytes:
    """The good request with one number written by hand."""
    payload = json.dumps(body())
    return payload.replace(f'"{field}": 600', f'"{field}": {text}').encode("utf-8")


def apply_request(verb: str, target: dict[str, Any], before: Any, after: Any) -> dict[str, Any]:
    """An apply request for one verb."""
    out = body()
    out["verb"] = verb
    out["target"] = target
    out["before"] = before
    out["after"] = after
    return out


# --------------------------------------------------------------------------
# The good request
# --------------------------------------------------------------------------


def test_the_good_request_parses() -> None:
    """A request that fits the contract is accepted as it stands."""
    parsed = request.parse_request(raw())

    assert parsed["device"] == "lab-win"
    assert parsed["target"]["bit"] == 4194304
    assert parsed["window"] == 600


def test_the_request_must_be_bytes() -> None:
    """Text is not a request."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request("{}")  # type: ignore[arg-type]

    assert caught.value.code == "schema"


def test_a_request_over_64_kib_is_refused() -> None:
    """The helper reads at most 64 KiB."""
    payload = raw()
    padded = payload[:-1] + b' ' * (64 * 1024) + b"}"

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(padded)

    assert caught.value.code == "schema"


def test_a_request_that_is_not_json_is_refused() -> None:
    """Broken JSON is a schema refusal."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(b"{not json")

    assert caught.value.code == "schema"


def test_a_request_that_is_not_an_object_is_refused() -> None:
    """A JSON array is not a request."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(b"[]")

    assert caught.value.code == "schema"


# --------------------------------------------------------------------------
# The schema rules of section 2
# --------------------------------------------------------------------------


def test_an_unknown_field_is_refused() -> None:
    """A field outside the list is refused."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw(extra="x"))

    assert caught.value.code == "schema"


def test_a_duplicate_key_is_refused() -> None:
    """The raw text is checked for a duplicate key."""
    payload = json.dumps(body())
    doubled = payload.replace('"v": 1', '"v": 1, "v": 1', 1)

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(doubled.encode("utf-8"))

    assert caught.value.code == "schema"


def test_two_keys_that_differ_only_in_case_are_refused() -> None:
    """Two keys that differ only in case are one key twice."""
    payload = json.dumps(body())
    doubled = payload.replace('"device": "lab-win"', '"Device": "lab-win", "device": "lab-win"', 1)

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(doubled.encode("utf-8"))

    assert caught.value.code == "schema"


def test_a_boolean_where_an_int_is_expected_is_refused() -> None:
    """A bool is not an int, even though Python says it is one."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw(window=True))

    assert caught.value.code == "schema"


def test_an_int_with_a_leading_zero_is_refused() -> None:
    """The int form has no leading zero."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw_number("window", "0600"))

    assert caught.value.code == "schema"


def test_an_int_with_a_fraction_is_refused() -> None:
    """The int form has no fraction."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw_number("window", "600.0"))

    assert caught.value.code == "schema"


def test_an_int_with_an_exponent_is_refused() -> None:
    """The int form has no exponent."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw_number("window", "6e2"))

    assert caught.value.code == "schema"


def test_a_negative_int_is_refused() -> None:
    """The int form has no sign."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw_number("window", "-600"))

    assert caught.value.code == "schema"


@pytest.mark.parametrize(
    "field,value",
    [
        ("v", 2),
        ("mode", "write"),
        ("device", "Lab-Win"),
        ("device", "lab win"),
        ("txid", "0123456789ABCDEF0123456789ABCDEF"),
        ("token", "A" * 64),
        ("risk", "low"),
        ("risk", "CRITICAL"),
        ("risk", ""),
    ],
)
def test_a_value_outside_its_pattern_is_refused(field: str, value: Any) -> None:
    """Every pattern of the field table is a refusal."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw(**{field: value}))

    assert caught.value.code == "schema"


def test_the_risk_is_required_in_an_apply() -> None:
    """The owner approves a level, so the level is in the request."""
    payload = body()
    del payload["risk"]

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(json.dumps(payload).encode("utf-8"))

    assert caught.value.code == "schema"


@pytest.mark.parametrize("level", ["LOW", "MED", "HIGH"])
def test_every_risk_level_is_accepted(level: str) -> None:
    """The three levels of the contract are the only ones."""
    parsed = request.parse_request(raw(risk=level))

    assert parsed["risk"] == level


@pytest.mark.parametrize(
    "field,value",
    [
        ("guid", "6f9619ff-8b86-d011-b42d-00c04fc964f"),
        ("guid", "6F9619FF-8B86-D011-B42D-00C04FC964FF"),
        ("sid", "S-1-5-21-1-2-3"),
        ("sid", "s-1-5-21-1-2-3-1105"),
        ("sam", "Seed"),
        ("sam", "-seed"),
        ("sam", "a" * 21),
    ],
)
def test_a_target_value_outside_its_pattern_is_refused(field: str, value: Any) -> None:
    """The GUID, SID and SAM patterns are refusals."""
    target = dict(ACCOUNT_TARGET)
    target[field] = value
    payload = apply_request("disable", target, {"uac": 512}, {"uac": 514})

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(json.dumps(payload).encode("utf-8"))

    assert caught.value.code == "schema"


def test_a_computer_sam_is_accepted() -> None:
    """A computer's sam is the user's sam plus a trailing dollar."""
    target = dict(ACCOUNT_TARGET)
    target["sam"] = "seed-asrep$"
    payload = apply_request("disable", target, {"uac": 512}, {"uac": 514})

    parsed = request.parse_request(json.dumps(payload).encode("utf-8"))

    assert parsed["target"]["sam"] == "seed-asrep$"


def test_a_window_outside_its_range_is_refused() -> None:
    """The window is 120..1800 seconds."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw(window=119))

    assert caught.value.code == "schema"

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw(window=1801))

    assert caught.value.code == "schema"


def test_the_window_of_an_unlock_is_120() -> None:
    """An unlock arms no undo, so its window is the unused 120."""
    payload = apply_request("unlock", ACCOUNT_TARGET, {"lockout": 5}, {"lockout": 0})

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(json.dumps({**payload, "window": 600}).encode("utf-8"))

    assert caught.value.code == "schema"

    parsed = request.parse_request(json.dumps({**payload, "window": 120}).encode("utf-8"))
    assert parsed["window"] == 120


def test_an_approval_window_that_is_too_wide_is_refused() -> None:
    """The approval window is at most 1800 seconds."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw(nbf=1800000000, exp=1800001801))

    assert caught.value.code == "schema"


def test_an_approval_window_that_does_not_move_forward_is_refused() -> None:
    """nbf must be before exp."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw(nbf=1800000600, exp=1800000600))

    assert caught.value.code == "schema"


def test_an_approval_window_that_is_not_ten_digits_is_refused() -> None:
    """The approval window is ten digits of UNIX seconds."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw(nbf=999999999, exp=1800000600))

    assert caught.value.code == "schema"


def test_a_field_that_the_mode_does_not_have_is_refused() -> None:
    """A status request carries no verb."""
    payload = {"v": 1, "mode": "status", "device": "lab-win", "txid": BASE["txid"], "verb": "uac-clear"}

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(json.dumps(payload).encode("utf-8"))

    assert caught.value.code == "schema"


def test_a_missing_field_is_refused() -> None:
    """Every field of the mode is required."""
    payload = body()
    del payload["token"]

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(json.dumps(payload).encode("utf-8"))

    assert caught.value.code == "schema"


def test_a_read_request_carries_no_txid() -> None:
    """A read needs no transaction id."""
    payload = {
        "v": 1,
        "mode": "read",
        "device": "lab-win",
        "verb": "uac-clear",
        "target": {"sam": "seed-asrep"},
    }

    parsed = request.parse_request(json.dumps(payload).encode("utf-8"))

    assert parsed["mode"] == "read"


def test_a_secret_outside_its_pattern_is_refused() -> None:
    """The secret is 16..128 printable ASCII."""
    payload = apply_request(
        "user-create",
        {"parent_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "sam": "newuser"},
        {"object": "absent"},
        {"object": "present"},
    )

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(json.dumps({**payload, "secret": "short"}).encode("utf-8"))

    assert caught.value.code == "schema"

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(json.dumps({**payload, "secret": "a" * 129}).encode("utf-8"))

    assert caught.value.code == "schema"

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(json.dumps({**payload, "secret": "a" * 15 + "\n"}).encode("utf-8"))

    assert caught.value.code == "schema"


def test_a_secret_is_only_for_a_user_create() -> None:
    """No other verb carries a secret."""
    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(raw(secret="a" * 24))

    assert caught.value.code == "schema"


def test_a_secret_is_accepted_for_a_user_create() -> None:
    """The user-create carries its password."""
    payload = apply_request(
        "user-create",
        {"parent_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "sam": "newuser"},
        {"object": "absent"},
        {"object": "present"},
    )

    parsed = request.parse_request(json.dumps({**payload, "secret": "a" * 24}).encode("utf-8"))

    assert parsed["secret"] == "a" * 24


# --------------------------------------------------------------------------
# The verb rules of section 3
# --------------------------------------------------------------------------


def test_uac_clear_accepts_a_bit_that_is_set() -> None:
    """The bit is set in the before-image and cleared in the after-image."""
    request.check_verb_rules(apply_request(
        "uac-clear",
        {**ACCOUNT_TARGET, "bit": 4194304},
        {"uac": 4260352},
        {"uac": 66048},
    ))


def test_uac_clear_refuses_a_bit_outside_the_set() -> None:
    """Only the five bits of the table may be cleared."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "uac-clear",
            {**ACCOUNT_TARGET, "bit": 2},
            {"uac": 4260352},
            {"uac": 66050},
        ))

    assert caught.value.code == "denied"


def test_uac_clear_refuses_a_bit_that_is_not_set() -> None:
    """The bit must be set in the before-image."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "uac-clear",
            {**ACCOUNT_TARGET, "bit": 4194304},
            {"uac": 66048},
            {"uac": 66048},
        ))

    assert caught.value.code == "denied"


def test_uac_clear_refuses_an_after_image_that_keeps_the_bit() -> None:
    """The after-image is the before-image without the bit."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "uac-clear",
            {**ACCOUNT_TARGET, "bit": 4194304},
            {"uac": 4260352},
            {"uac": 4260352},
        ))

    assert caught.value.code == "denied"


def test_disable_accepts_an_enabled_account() -> None:
    """The disable sets the ACCOUNTDISABLE bit."""
    request.check_verb_rules(apply_request(
        "disable", ACCOUNT_TARGET, {"uac": 512}, {"uac": 514}
    ))


def test_disable_refuses_an_account_that_is_already_disabled() -> None:
    """The ACCOUNTDISABLE bit must be clear in the before-image."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "disable", ACCOUNT_TARGET, {"uac": 514}, {"uac": 514}
        ))

    assert caught.value.code == "denied"


def test_disable_refuses_an_after_image_that_changes_more() -> None:
    """The after-image is the before-image with the bit set."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "disable", ACCOUNT_TARGET, {"uac": 512}, {"uac": 516}
        ))

    assert caught.value.code == "denied"


def test_disable_refuses_the_administrator() -> None:
    """RID 500 is never disabled."""
    target = {**ACCOUNT_TARGET, "sid": "S-1-5-21-1-2-3-500"}

    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "disable", target, {"uac": 512}, {"uac": 514}
        ))

    assert caught.value.code == "denied"


def test_enable_accepts_a_disabled_account() -> None:
    """The enable clears the ACCOUNTDISABLE bit."""
    request.check_verb_rules(apply_request(
        "enable", ACCOUNT_TARGET, {"uac": 514}, {"uac": 512}
    ))


def test_enable_refuses_an_account_that_is_not_disabled() -> None:
    """The ACCOUNTDISABLE bit must be set in the before-image."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "enable", ACCOUNT_TARGET, {"uac": 512}, {"uac": 512}
        ))

    assert caught.value.code == "denied"


def test_enable_refuses_an_after_image_that_changes_more() -> None:
    """The after-image is the before-image without the bit."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "enable", ACCOUNT_TARGET, {"uac": 514}, {"uac": 510}
        ))

    assert caught.value.code == "denied"


def test_enc_types_accepts_a_change_that_keeps_the_high_bits() -> None:
    """The bits above 63 may not change."""
    request.check_verb_rules(apply_request(
        "enc-types", ACCOUNT_TARGET, {"etypes": 0}, {"etypes": 16}
    ))


def test_enc_types_refuses_des() -> None:
    """DES is never enabled."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "enc-types", ACCOUNT_TARGET, {"etypes": 0}, {"etypes": 1}
        ))

    assert caught.value.code == "denied"


def test_enc_types_refuses_a_change_of_the_high_bits() -> None:
    """The bits above 63 may not change."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "enc-types", ACCOUNT_TARGET, {"etypes": 0}, {"etypes": 16 | 128}
        ))

    assert caught.value.code == "denied"


def test_enc_types_refuses_no_change() -> None:
    """The encryption types must change."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "enc-types", ACCOUNT_TARGET, {"etypes": 16}, {"etypes": 16}
        ))

    assert caught.value.code == "denied"


def test_enc_types_treats_an_absent_before_image_as_zero() -> None:
    """An absent before-image counts as zero."""
    request.check_verb_rules(apply_request(
        "enc-types", ACCOUNT_TARGET, {"etypes": "absent"}, {"etypes": 16}
    ))


def test_unlock_accepts_a_locked_account() -> None:
    """The unlock sets the lockout to zero."""
    request.check_verb_rules(apply_request(
        "unlock", ACCOUNT_TARGET, {"lockout": 5}, {"lockout": 0}
    ))


def test_unlock_refuses_an_account_that_is_not_locked() -> None:
    """The lockout must be above zero in the before-image."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "unlock", ACCOUNT_TARGET, {"lockout": 0}, {"lockout": 0}
        ))

    assert caught.value.code == "denied"


def test_unlock_refuses_an_after_image_that_is_not_zero() -> None:
    """The after-image of an unlock is zero."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "unlock", ACCOUNT_TARGET, {"lockout": 5}, {"lockout": 1}
        ))

    assert caught.value.code == "denied"


MEMBER_TARGET = {
    "group_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
    "group_sid": "S-1-5-21-1-2-3-1105",
    "group_sam": "seed-asrep",
    "member_guid": "7f9619ff-8b86-d011-b42d-00c04fc964ff",
    "member_sid": "S-1-5-21-1-2-3-1106",
    "member_sam": "other",
}


def test_member_add_accepts_a_member_that_is_not_in_the_group() -> None:
    """The member-add goes from absent to present."""
    request.check_verb_rules(apply_request(
        "member-add", MEMBER_TARGET, {"member": "absent"}, {"member": "present"}
    ))


def test_member_add_refuses_a_member_that_is_already_in_the_group() -> None:
    """The member-add starts from absent."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "member-add", MEMBER_TARGET, {"member": "present"}, {"member": "present"}
        ))

    assert caught.value.code == "denied"


def test_member_remove_accepts_a_member_that_is_in_the_group() -> None:
    """The member-remove goes from present to absent."""
    request.check_verb_rules(apply_request(
        "member-remove", MEMBER_TARGET, {"member": "present"}, {"member": "absent"}
    ))


def test_member_remove_refuses_a_member_that_is_not_in_the_group() -> None:
    """The member-remove starts from present."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "member-remove", MEMBER_TARGET, {"member": "absent"}, {"member": "absent"}
        ))

    assert caught.value.code == "denied"


@pytest.mark.parametrize("sam", ["newton-ops", "NEWTON-OPS"])
def test_the_write_account_sam_is_never_a_target(sam: str) -> None:
    """The host refuses the write account before a helper is contacted."""
    target = {**ACCOUNT_TARGET, "sam": sam}

    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "disable", target, {"uac": 512}, {"uac": 514}
        ))

    assert caught.value.code == "denied"


@pytest.mark.parametrize("sam", ["newton-ops", "NEWTON-OPS"])
def test_the_write_account_sam_is_never_a_member(sam: str) -> None:
    """Membership writes refuse the write account's name case-insensitively."""
    target = {**MEMBER_TARGET, "member_sam": sam}

    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "member-add", target, {"member": "absent"}, {"member": "present"}
        ))

    assert caught.value.code == "denied"


@pytest.mark.parametrize("sam", ["krbtgt", "KRBTGT", "krbtgt_1000", "KRBTGT_1000"])
def test_a_krbtgt_sam_is_never_a_target(sam: str) -> None:
    """The host refuses krbtgt and RODC krbtgt names case-insensitively."""
    target = {**ACCOUNT_TARGET, "sam": sam}

    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "disable", target, {"uac": 512}, {"uac": 514}
        ))

    assert caught.value.code == "denied"


@pytest.mark.parametrize("sam", ["krbtgt", "KRBTGT_1000"])
def test_a_krbtgt_sam_is_never_a_member(sam: str) -> None:
    """The host also refuses a krbtgt account as a membership member."""
    target = {**MEMBER_TARGET, "member_sam": sam}

    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "member-remove", target, {"member": "present"}, {"member": "absent"}
        ))

    assert caught.value.code == "denied"


def test_maq_accepts_a_quota_in_range() -> None:
    """The quota is 0..1000."""
    request.check_verb_rules(apply_request(
        "maq", {"guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff"}, {"maq": 10}, {"maq": 0}
    ))


def test_maq_refuses_a_quota_out_of_range() -> None:
    """The quota is 0..1000."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "maq", {"guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff"}, {"maq": 10}, {"maq": 1001}
        ))

    assert caught.value.code == "denied"


def test_user_create_accepts_an_absent_object() -> None:
    """The user-create goes from absent to present."""
    request.check_verb_rules(apply_request(
        "user-create",
        {"parent_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "sam": "newuser"},
        {"object": "absent"},
        {"object": "present"},
    ))


def test_user_create_refuses_an_object_that_is_there() -> None:
    """The user-create starts from absent."""
    with pytest.raises(request.RequestRefused) as caught:
        request.check_verb_rules(apply_request(
            "user-create",
            {"parent_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "sam": "newuser"},
            {"object": "present"},
            {"object": "present"},
        ))

    assert caught.value.code == "denied"


def test_move_accepts_a_new_parent() -> None:
    """The move names the new parent."""
    request.check_verb_rules(apply_request(
        "move",
        ACCOUNT_TARGET,
        {"parent": "6f9619ff-8b86-d011-b42d-00c04fc964ff"},
        {"parent": "8f9619ff-8b86-d011-b42d-00c04fc964ff"},
    ))


def test_move_refuses_a_parent_that_is_not_a_guid() -> None:
    """The parent of a move is a GUID."""
    payload = apply_request(
        "move",
        ACCOUNT_TARGET,
        {"parent": "6f9619ff-8b86-d011-b42d-00c04fc964ff"},
        {"parent": "ou=users"},
    )

    with pytest.raises(request.RequestRefused) as caught:
        request.parse_request(json.dumps(payload).encode("utf-8"))

    assert caught.value.code == "schema"


# --------------------------------------------------------------------------
# The canonical bytes of section 4
# --------------------------------------------------------------------------


def test_the_canonical_bytes_hold_the_lines_in_order() -> None:
    """The canonical bytes are the ten lines of the spec, in order."""
    canonical = request.canonical_bytes(body()).decode("ascii")

    assert canonical == (
        "newton-ad-request-v1\n"
        "device=lab-win\n"
        "txid=0123456789abcdef0123456789abcdef\n"
        "verb=uac-clear\n"
        "target=bit=4194304,guid=6f9619ff-8b86-d011-b42d-00c04fc964ff,"
        "sam=seed-asrep,sid=S-1-5-21-1-2-3-1105\n"
        "before=uac=4260352\n"
        "after=uac=66048\n"
        "window=600\n"
        "risk=MED\n"
        "secret=-\n"
        "helper=1\n"
    )


def test_the_canonical_bytes_hold_the_risk_between_the_window_and_the_secret() -> None:
    """The risk is signed: it is in the canonical bytes, in its own line."""
    canonical = request.canonical_bytes(body(risk="HIGH")).decode("ascii")

    lines = canonical.splitlines()
    assert lines.index("risk=HIGH") == lines.index("window=600") + 1
    assert lines.index("risk=HIGH") + 1 == lines.index("secret=-")


def test_the_canonical_bytes_change_with_the_risk() -> None:
    """Two levels of the same change have two digests."""
    assert request.digest(body(risk="LOW")) != request.digest(body(risk="HIGH"))


def test_the_canonical_bytes_sort_the_keys_by_byte_value() -> None:
    """The keys are sorted ordinally, not by insertion order."""
    one = request.canonical_bytes(body(target={
        "sam": "seed-asrep", "bit": 4194304, "sid": "S-1-5-21-1-2-3-1105",
        "guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
    }))
    other = request.canonical_bytes(body(target={
        "guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "bit": 4194304,
        "sid": "S-1-5-21-1-2-3-1105", "sam": "seed-asrep",
    }))

    assert one == other
    assert b"target=bit=" in one


def test_the_canonical_bytes_write_an_int_without_a_sign_or_a_zero() -> None:
    """An int is decimal, with no sign and no leading zero."""
    canonical = request.canonical_bytes(body(window=600)).decode("ascii")

    assert "window=600\n" in canonical
    assert "+600" not in canonical
    assert "0600" not in canonical


def test_the_canonical_bytes_write_an_absent_value_as_it_is() -> None:
    """The word absent is a value, not an int."""
    payload = apply_request(
        "user-create",
        {"parent_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "sam": "newuser"},
        {"object": "absent"},
        {"object": "present"},
    )

    canonical = request.canonical_bytes(payload).decode("ascii")

    assert "before=object=absent\n" in canonical
    assert "after=object=present\n" in canonical


def test_the_canonical_bytes_never_hold_the_secret() -> None:
    """The secret is hashed, never written."""
    payload = apply_request(
        "user-create",
        {"parent_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "sam": "newuser"},
        {"object": "absent"},
        {"object": "present"},
    )
    payload["secret"] = "s3cret-pass-word-24-chars"

    canonical = request.canonical_bytes(payload)

    assert b"s3cret-pass-word-24-chars" not in canonical
    assert b"secret=-" not in canonical
    assert canonical.count(b"secret=") == 1


def test_the_canonical_bytes_hash_the_secret() -> None:
    """The secret line is the sha256 of the secret's ASCII bytes."""
    import hashlib

    payload = apply_request(
        "user-create",
        {"parent_guid": "6f9619ff-8b86-d011-b42d-00c04fc964ff", "sam": "newuser"},
        {"object": "absent"},
        {"object": "present"},
    )
    payload["secret"] = "s3cret-pass-word-24-chars"

    canonical = request.canonical_bytes(payload).decode("ascii")
    expected = hashlib.sha256(b"s3cret-pass-word-24-chars").hexdigest()

    assert f"secret={expected}\n" in canonical


def test_the_digest_is_the_sha256_of_the_canonical_bytes() -> None:
    """The digest is the hash of the canonical bytes."""
    import hashlib

    canonical = request.canonical_bytes(body())

    assert request.digest(body()) == hashlib.sha256(canonical).hexdigest()
    assert len(request.digest(body())) == 64


def test_the_token_is_the_router_token() -> None:
    """The token is the one the router flow mints."""
    from newton_mcp import approve

    k_hex = "11" * 32
    digest = request.digest(body())

    assert request.token(k_hex, digest, 1800000000, 1800000600) == approve.approval_token(
        k_hex, digest, 1800000000, 1800000600
    )
