"""The value decoders: SID, GUID, FILETIME, GeneralizedTime and the flags.

The vectors here are the documented ones: a SID round trip, the mixed-endian
GUID and the two "never" FILETIME values.
"""

from __future__ import annotations

import base64
import struct
from datetime import datetime, timezone

import pytest

from newton_mcp.ad import values


DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"
ADMIN_SID = f"{DOMAIN_SID}-500"


def sid_bytes(
    revision: int = 1,
    authority: int = 5,
    sub_authorities: tuple[int, ...] = (),
) -> bytes:
    """Build the binary SID the way a collector reports it."""
    out = bytearray([revision, len(sub_authorities)])
    out += authority.to_bytes(6, "big")
    for sub in sub_authorities:
        out += sub.to_bytes(4, "little")
    return bytes(out)


def test_a_sid_round_trips_through_its_binary_form() -> None:
    """The binary SID decodes to the canonical text form."""
    raw = sid_bytes(1, 5, (21, 1004336348, 1177238915, 682003330, 512))

    assert values.sid_from_bytes(raw) == f"{DOMAIN_SID}-512"


def test_the_sid_text_is_the_same_in_both_directions() -> None:
    """The base64 blob of a SID decodes to the same text."""
    raw = sid_bytes(1, 5, (21, 1004336348, 1177238915, 682003330, 512))

    encoded = base64.b64encode(raw).decode("ascii")

    assert values.sid_from_base64(encoded) == f"{DOMAIN_SID}-512"


def test_a_short_sid_blob_is_refused() -> None:
    """A blob that is too short is not a SID."""
    with pytest.raises(ValueError):
        values.sid_from_bytes(b"\x01\x05\x00")


def test_a_sid_blob_with_the_wrong_length_is_refused() -> None:
    """A blob whose length does not match the count is not a SID."""
    with pytest.raises(ValueError):
        values.sid_from_bytes(sid_bytes(1, 5, (21, 1004336348)) + b"\x00\x00")


def test_a_sid_blob_that_is_not_base64_is_refused() -> None:
    """Base64 that does not decode is refused."""
    with pytest.raises(ValueError):
        values.sid_from_base64("not base64 at all")


def test_a_guid_decodes_the_way_windows_stores_it() -> None:
    """The mixed-endian GUID becomes the canonical lowercase text."""
    raw = b"\x33\x22\x11\x00\x55\x44\x77\x66\x88\x99\xaa\xbb\xcc\xdd\xee\xff"

    assert values.guid_from_bytes(raw) == "00112233-4455-6677-8899-aabbccddeeff"


def test_a_guid_of_the_wrong_length_is_refused() -> None:
    """A GUID is exactly 16 bytes."""
    with pytest.raises(ValueError):
        values.guid_from_bytes(b"\x00" * 15)


def test_a_guid_round_trips_through_base64() -> None:
    """The base64 blob of a GUID decodes to the same text."""
    raw = b"\x33\x22\x11\x00\x55\x44\x77\x66\x88\x99\xaa\xbb\xcc\xdd\xee\xff"

    encoded = base64.b64encode(raw).decode("ascii")

    assert values.guid_from_base64(encoded) == (
        "00112233-4455-6677-8899-aabbccddeeff"
    )


def test_the_never_filetime_values_are_none() -> None:
    """Zero and the largest int64 mean "never"."""
    assert values.filetime_to_datetime(0) is None
    assert values.filetime_to_datetime(0x7FFFFFFFFFFFFFFF) is None


def test_a_filetime_decodes_to_utc() -> None:
    """A FILETIME is the number of 100-nanosecond ticks since 1601."""
    # 2000-01-01T00:00:00Z is 12591158400 seconds after the Windows epoch.
    raw = 12591158400 * 10_000_000

    decoded = values.filetime_to_datetime(raw)

    assert decoded == datetime(2000, 1, 1, tzinfo=timezone.utc)


def test_a_filetime_keeps_the_sub_second_part() -> None:
    """The fractional second survives the conversion."""
    raw = 12591158400 * 10_000_000 + 1234567

    decoded = values.filetime_to_datetime(raw)

    assert decoded is not None
    assert decoded.microsecond == 123456


def test_a_generalized_time_without_a_t_is_accepted() -> None:
    """The prose in section 5 spells the time without the "T"."""
    parsed = values.parse_gentime("20261108120000.0Z")

    assert parsed == datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)


def test_a_filetime_out_of_range_is_refused() -> None:
    """A negative FILETIME is not a timestamp."""
    with pytest.raises(ValueError):
        values.filetime_to_datetime(-1)


def test_a_generalized_time_is_utc() -> None:
    """The collectors write UTC with a zero fraction."""
    parsed = values.parse_gentime("20261108T120000.0Z")

    assert parsed == datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)


def test_a_generalized_time_without_a_fraction_is_accepted() -> None:
    """A collector that writes no fraction is still read."""
    parsed = values.parse_gentime("20261108T120000Z")

    assert parsed == datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)


def test_a_generalized_time_that_is_not_one_is_refused() -> None:
    """Anything that is not the expected shape is refused."""
    with pytest.raises(ValueError):
        values.parse_gentime("2026-11-08T12:00:00Z")


def test_a_generalized_time_that_is_not_a_real_time_is_refused() -> None:
    """The shape is right but the date is not."""
    with pytest.raises(ValueError):
        values.parse_gentime("20261308T120000.0Z")


def test_the_rid_of_a_sid_is_its_last_component() -> None:
    """The RID is the number after the last dash."""
    assert values.rid(ADMIN_SID) == 500
    assert values.rid(f"{DOMAIN_SID}-512") == 512


def test_the_rid_of_something_that_is_not_a_sid_is_none() -> None:
    """A name is not a SID and has no RID."""
    assert values.rid("Administrator") is None
    assert values.rid("") is None


def test_a_sid_is_recognised() -> None:
    """Only well-formed SIDs are SIDs."""
    assert values.is_sid(ADMIN_SID) is True
    assert values.is_sid("S-1-5-21-1-2-3-4-5") is True
    assert values.is_sid("S-1-5") is True
    assert values.is_sid("S-1-5-21-abc") is False
    assert values.is_sid("s-1-5-21") is False
    assert values.is_sid("") is False
    assert values.is_sid(None) is False


def test_a_sid_that_ends_in_a_newline_is_not_a_sid() -> None:
    """The SID pattern is matched whole, never up to a newline."""
    assert values.is_sid(f"{ADMIN_SID}\n") is False
    assert values.is_sid(f"{ADMIN_SID}\r\n") is False


def test_a_guid_that_ends_in_a_newline_is_not_a_guid() -> None:
    """The GUID pattern is matched whole, never up to a newline."""
    assert values.is_guid("00112233-4455-6677-8899-aabbccddeeff\n") is False


def test_a_sub_authority_with_a_leading_zero_is_not_a_sid() -> None:
    """A sub-authority is a canonical decimal number."""
    assert values.is_sid("S-1-5-21-1-2-3-0512") is False
    assert values.is_sid("S-1-5-21-1-2-3-00") is False


def test_a_sid_is_canonicalised_before_it_is_compared() -> None:
    """The canonical form of a SID is the one that is compared."""
    assert values.canonical_sid("S-01-5-21-1-2-3-512") == "S-1-5-21-1-2-3-512"
    assert values.canonical_sid(ADMIN_SID) == ADMIN_SID


def test_a_sid_that_is_not_a_sid_is_refused_by_the_canonical_form() -> None:
    """The canonical form of something that is not a SID is refused."""
    with pytest.raises(ValueError):
        values.canonical_sid("S-1-5-21-1-2-3-0512")


def test_a_filetime_that_overflows_is_refused() -> None:
    """A FILETIME no datetime can hold is refused, not raised as overflow."""
    with pytest.raises(ValueError):
        values.filetime_to_datetime(2**62)


def test_a_dn_key_ignores_case_and_the_spaces_around_the_separators() -> None:
    """Two names that differ in case or spacing are one name."""
    assert values.dn_key("CN=svc, OU=People, DC=win") == values.dn_key(
        "cn=svc,ou=people,dc=win"
    )
    assert values.dn_key(" CN = svc , DC = win ") == "cn=svc,dc=win"


def test_a_dn_key_decodes_the_hex_escapes() -> None:
    """An escaped character is the character it stands for."""
    assert values.dn_key("CN=John\\20Smith,DC=win") == "cn=john smith,dc=win"


def test_an_escaped_comma_does_not_split_the_name() -> None:
    """An escaped comma is part of the name, not a separator."""
    assert values.dn_key("CN=Lastname\\2CFirst,DC=win") == (
        "cn=lastname,first,dc=win"
    )


def test_a_dn_key_keeps_the_rdns_apart() -> None:
    """Each RDN of the name is one part of the key."""
    assert values.dn_key("CN=svc,OU=People,DC=win") == "cn=svc,ou=people,dc=win"


def test_the_rdns_of_a_name_are_a_list() -> None:
    """A name is a list of RDNs, and the key is the join of that list."""
    name = "CN=Lastname\\2CFirst, OU=People, DC=win"

    assert values.dn_rdns(name) == (
        "cn=lastname,first",
        "ou=people",
        "dc=win",
    )
    assert values.dn_key(name) == ",".join(values.dn_rdns(name))


def test_an_escaped_comma_is_one_rdn() -> None:
    """An escaped comma is part of the RDN, not a separator."""
    assert values.dn_rdns("CN=User,DC=Win\\,DC=newton,DC=test") == (
        "cn=user",
        "dc=win,dc=newton",
        "dc=test",
    )


def test_a_display_name_decodes_the_hex_escapes_as_utf_8() -> None:
    """The hex escapes of a name are the bytes of its UTF-8 text."""
    assert values.dn_display_name(r"CN=J\C3\BCrgen,OU=A") == "Jürgen"


def test_a_display_name_decodes_a_run_of_hex_escapes_as_utf_8() -> None:
    """A run of hex escapes is one run of bytes, decoded together."""
    assert values.dn_display_name(r"CN=a\2Cb\C3\A9,OU=A") == "a,bé"


def test_a_display_name_with_bytes_that_are_not_utf_8_is_replaced() -> None:
    """Bytes that are not valid UTF-8 become the replacement character."""
    assert values.dn_display_name(r"CN=x\C3,OU=A") == "x�"


def test_a_dn_key_decodes_the_hex_escapes_as_utf_8() -> None:
    """A name written in escapes is the name written in UTF-8."""
    assert values.dn_key(r"CN=J\C3\BCrgen,OU=A") == values.dn_key(
        "CN=Jürgen,OU=A"
    )


def test_the_rid_of_a_sid_of_another_domain_is_none() -> None:
    """The RID only means something inside its own domain."""
    other = "S-1-5-21-9999999999-9999999999-9999999999-500"

    assert values.rid_in_domain(other, DOMAIN_SID) is None
    assert values.rid_in_domain(f"{DOMAIN_SID}-500", DOMAIN_SID) == 500


def test_the_account_control_names_are_the_documented_table() -> None:
    """A userAccountControl value decodes to the MS-ADTS names."""
    # 0x202 is a disabled normal account.
    assert values.uac_flag_names(0x202) == ("ACCOUNTDISABLE", "NORMAL_ACCOUNT")
    # 0x400200 is a normal account that does not require pre-authentication.
    assert values.uac_flag_names(0x400200) == (
        "NORMAL_ACCOUNT",
        "DONT_REQUIRE_PREAUTH",
    )
    assert values.uac_flag_names(0) == ()


def test_the_account_control_table_is_the_documented_one() -> None:
    """Every named bit of userAccountControl is the MS-ADTS one."""
    assert values.UAC_FLAGS == {
        0x00000001: "SCRIPT",
        0x00000002: "ACCOUNTDISABLE",
        0x00000008: "HOMEDIR_REQUIRED",
        0x00000010: "LOCKOUT",
        0x00000020: "PASSWD_NOTREQD",
        0x00000040: "PASSWD_CANT_CHANGE",
        0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED",
        0x00000100: "TEMP_DUPLICATE_ACCOUNT",
        0x00000200: "NORMAL_ACCOUNT",
        0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
        0x00001000: "WORKSTATION_TRUST_ACCOUNT",
        0x00002000: "SERVER_TRUST_ACCOUNT",
        0x00010000: "DONT_EXPIRE_PASSWORD",
        0x00020000: "MNS_LOGON_ACCOUNT",
        0x00040000: "SMARTCARD_REQUIRED",
        0x00080000: "TRUSTED_FOR_DELEGATION",
        0x00100000: "NOT_DELEGATED",
        0x00200000: "USE_DES_KEY_ONLY",
        0x00400000: "DONT_REQUIRE_PREAUTH",
        0x00800000: "PASSWORD_EXPIRED",
        0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
        0x04000000: "PARTIAL_SECRETS_ACCOUNT",
    }


def test_the_encryption_type_names_are_the_documented_table() -> None:
    """The encryption types decode to their names."""
    assert values.enc_type_flag_names(0x18) == ("AES128", "AES256")
    assert values.enc_type_flag_names(0) == ()


def test_the_encryption_type_table_is_the_documented_one() -> None:
    """Every named bit of msDS-SupportedEncryptionTypes is the MS-ADTS one."""
    assert values.ENC_TYPE_FLAGS == {
        0x00000001: "DES_CBC_CRC",
        0x00000002: "DES_CBC_MD5",
        0x00000004: "RC4",
        0x00000008: "AES128",
        0x00000010: "AES256",
        0x00000020: "AES256_SK",
        0x00010000: "FAST_SUPPORTED",
    }


def test_a_flag_value_that_is_not_an_integer_is_refused() -> None:
    """The decoders do not guess."""
    with pytest.raises(ValueError):
        values.uac_flag_names("512")
    with pytest.raises(ValueError):
        values.enc_type_flag_names(None)


def test_the_sid_layout_is_the_documented_one() -> None:
    """The bytes are read the way MS-DTYP writes them."""
    raw = struct.pack("<BB", 1, 1) + (5).to_bytes(6, "big")
    raw += struct.pack("<I", 21)

    assert values.sid_from_bytes(raw) == "S-1-5-21"


def test_the_d_s_heuristics_positions_are_read() -> None:
    """The dSHeuristics string holds one hex digit per position.

    The positions are the ones the specification counts: the first
    character of the attribute is position 1.
    """
    assert values.ds_heuristics_positions("0001000100") == {
        1: 0,
        2: 0,
        3: 0,
        4: 1,
        5: 0,
        6: 0,
        7: 0,
        8: 1,
        9: 0,
        10: 0,
    }
    assert values.ds_heuristics_positions("30") == {1: 3, 2: 0}
    assert values.ds_heuristics_positions("") == {}


def test_a_d_s_heuristics_that_is_not_hexadecimal_is_refused() -> None:
    """The decoder does not guess, and the message holds no text."""
    with pytest.raises(ValueError):
        values.ds_heuristics_positions("30x")
    with pytest.raises(ValueError):
        values.ds_heuristics_positions(None)


def test_the_functional_level_names_are_the_documented_table() -> None:
    """A functional level decodes to the name of its release."""
    assert values.functional_level_name(0) == "Windows 2000"
    assert values.functional_level_name(6) == "Windows Server 2012 R2"
    assert values.functional_level_name(10) == "Windows Server 2025"
    assert values.functional_level_name(99) == "unknown level 99"


def test_a_functional_level_that_is_not_an_integer_is_refused() -> None:
    """The decoder does not guess."""
    with pytest.raises(ValueError):
        values.functional_level_name("10")
    with pytest.raises(ValueError):
        values.functional_level_name(-1)


def test_the_trust_attribute_names_are_the_documented_table() -> None:
    """The trust attributes decode to their names."""
    assert values.trust_attribute_names(0x04) == ("QUARANTINED_DOMAIN",)
    assert values.trust_attribute_names(0x0C) == (
        "QUARANTINED_DOMAIN",
        "FOREST_TRANSITIVE",
    )
    assert values.trust_attribute_names(0x20) == ("WITHIN_FOREST",)
    assert values.trust_attribute_names(0x40) == ("TREAT_AS_EXTERNAL",)
    assert values.trust_attribute_names(0) == ()


def test_a_trust_attribute_value_that_is_not_an_integer_is_refused() -> None:
    """The decoder does not guess."""
    with pytest.raises(ValueError):
        values.trust_attribute_names("12")
    with pytest.raises(ValueError):
        values.trust_attribute_names(None)


def test_a_timespan_is_read_in_seconds() -> None:
    """The directory counts a timespan in 100-nanosecond units."""
    # 42 days, the default maximum age of a password.
    assert values.timespan_seconds(-36288000000000) == 3628800.0
    # 10 minutes, the default lockout duration.
    assert values.timespan_seconds(-6000000000) == 600.0
    assert values.timespan_seconds(0) == 0.0


def test_a_timespan_that_is_not_an_integer_is_refused() -> None:
    """The decoder does not guess."""
    with pytest.raises(ValueError):
        values.timespan_seconds("600")
    with pytest.raises(ValueError):
        values.timespan_seconds(None)
