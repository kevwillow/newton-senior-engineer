"""The security descriptor reader, on descriptors built in the test.

No measured descriptor exists yet (SPEC-1.3 section 10 keeps measured
documents for the fixtures), so every descriptor here is built with
``struct`` from the documented layout: the self-relative header, the
owner, the group and the DACL.

The object ACE is the layout of MS-DTYP 2.4.4.3: the header, the mask,
the four-byte flags that say which of the two GUIDs are there, the GUIDs
that are there and the SID.
"""

from __future__ import annotations

import struct
from typing import Any

import pytest

from newton_mcp.ad import secdesc


OWNER_SID = "S-1-5-21-1004336348-1177238915-682003330-500"
GROUP_SID = "S-1-5-21-1004336348-1177238915-682003330-513"
TRUSTEE_SID = "S-1-5-21-1004336348-1177238915-682003330-1107"
DOMAIN_ADMINS_SID = "S-1-5-21-1004336348-1177238915-682003330-512"
OBJECT_TYPE = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
INHERITED_TYPE = "89e95b76-444d-4c62-991a-0facbeda640c"
GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


def sid_binary(sid: str) -> bytes:
    """The binary SID, the way a directory writes it."""
    parts = sid.split("-")
    out = bytearray([int(parts[1]), len(parts) - 3])
    out += int(parts[2]).to_bytes(6, "big")
    for part in parts[3:]:
        out += int(part).to_bytes(4, "little")
    return bytes(out)


def guid_binary(guid: str) -> bytes:
    """The binary GUID, the way Windows writes it."""
    text = guid.replace("-", "")
    return (
        bytes.fromhex(text[0:8])[::-1]
        + bytes.fromhex(text[8:12])[::-1]
        + bytes.fromhex(text[12:16])[::-1]
        + bytes.fromhex(text[16:32])
    )


def ace(
    ace_type: int,
    flags: int,
    mask: int,
    trustee: str,
    *,
    object_type: str | None = None,
    inherited_object_type: str | None = None,
) -> bytes:
    """One ACE, in the layout of MS-DTYP 2.4.4.

    An object ACE carries the four-byte flags of MS-DTYP 2.4.4.3: the
    bit that says the object type is there and the bit that says the
    inherited object type is there.  Only the GUIDs whose bit is set
    are written.
    """
    body = struct.pack("<I", mask)
    if ace_type in secdesc.OBJECT_ACE_TYPES:
        object_flags = 0
        if object_type is not None:
            object_flags |= secdesc.ACE_OBJECT_TYPE_PRESENT
        if inherited_object_type is not None:
            object_flags |= secdesc.ACE_INHERITED_OBJECT_TYPE_PRESENT
        body += struct.pack("<I", object_flags)
        if object_type is not None:
            body += guid_binary(object_type)
        if inherited_object_type is not None:
            body += guid_binary(inherited_object_type)
    body += sid_binary(trustee)
    return struct.pack("<BBH", ace_type, flags, 4 + len(body)) + body


def build(
    *,
    owner: str | None = OWNER_SID,
    group: str | None = GROUP_SID,
    aces: list[bytes] | None = None,
    dacl: bytes | None = None,
    revision: int = 1,
    dacl_kind: str = "present",
) -> bytes:
    """A self-relative descriptor with the given owner, group and DACL.

    The DACL kind is the shape of the control: ``present`` writes the
    DACL and sets SE_DACL_PRESENT, ``null`` sets SE_DACL_PRESENT and
    leaves the DACL offset at zero, and ``absent`` leaves the bit and
    the offset alone.
    """
    owner_bytes = sid_binary(owner) if owner else b""
    group_bytes = sid_binary(group) if group else b""
    control = secdesc.SE_SELF_RELATIVE
    dacl_bytes = b""
    dacl_offset = 0
    if dacl_kind == "present":
        control |= secdesc.SE_DACL_PRESENT
        body = b"".join(aces or [])
        dacl_bytes = (
            dacl
            if dacl is not None
            else struct.pack("<BBHHH", 2, 0, 8 + len(body), len(aces or []), 0)
            + body
        )
    elif dacl_kind == "null":
        control |= secdesc.SE_DACL_PRESENT
    elif dacl_kind != "absent":
        raise ValueError("the dacl kind is not known")

    owner_offset = 20 if owner_bytes else 0
    group_offset = owner_offset + len(owner_bytes) if group_bytes else 0
    if dacl_bytes:
        dacl_offset = group_offset + len(group_bytes)
    header = struct.pack(
        "<BBHIIII",
        revision,
        0,
        control,
        owner_offset,
        group_offset,
        0,
        dacl_offset,
    )
    return header + owner_bytes + group_bytes + dacl_bytes


def test_the_owner_the_group_and_the_aces_are_read() -> None:
    """A descriptor with two ACEs is read as it was built."""
    raw = build(
        aces=[
            ace(secdesc.ACCESS_ALLOWED_ACE, 0x00, 0x1F01FF, TRUSTEE_SID),
            ace(secdesc.ACCESS_DENIED_ACE, 0x10, 0x200, TRUSTEE_SID),
        ]
    )

    descriptor = secdesc.parse(raw)

    assert descriptor.revision == 1
    assert descriptor.owner == OWNER_SID
    assert descriptor.group == GROUP_SID
    assert len(descriptor.dacl) == 2
    first = descriptor.dacl[0]
    assert isinstance(first, secdesc.Ace)
    assert first.type == secdesc.ACCESS_ALLOWED_ACE
    assert first.mask == 0x1F01FF
    assert first.trustee == TRUSTEE_SID
    second = descriptor.dacl[1]
    assert isinstance(second, secdesc.Ace)
    assert second.type == secdesc.ACCESS_DENIED_ACE
    assert second.flags == 0x10


def test_an_object_ace_carries_its_two_guids() -> None:
    """An object ACE names the type it applies to."""
    raw = build(
        aces=[
            ace(
                secdesc.ACCESS_ALLOWED_OBJECT_ACE,
                0x00,
                secdesc.ADS_RIGHT_DS_CONTROL_ACCESS,
                TRUSTEE_SID,
                object_type=OBJECT_TYPE,
                inherited_object_type=INHERITED_TYPE,
            )
        ]
    )

    descriptor = secdesc.parse(raw)
    entry = descriptor.dacl[0]
    assert isinstance(entry, secdesc.Ace)
    assert entry.object_type == OBJECT_TYPE
    assert entry.inherited_object_type == INHERITED_TYPE
    assert entry.mask == secdesc.ADS_RIGHT_DS_CONTROL_ACCESS


def test_an_unknown_ace_type_is_kept_and_never_raises() -> None:
    """A type Newton does not read is still an ACE."""
    raw = build(
        aces=[
            ace(0x02, 0x00, 0x1, TRUSTEE_SID),
            ace(secdesc.ACCESS_ALLOWED_ACE, 0x00, 0x1, TRUSTEE_SID),
        ]
    )

    descriptor = secdesc.parse(raw)

    assert isinstance(descriptor.dacl[0], secdesc.UnknownAce)
    assert descriptor.dacl[0].type == 0x02
    assert descriptor.dacl[0].size == 8 + len(sid_binary(TRUSTEE_SID))
    assert isinstance(descriptor.dacl[1], secdesc.Ace)


def test_the_inherit_only_flag_is_named() -> None:
    """The flags of an ACE are read as names."""
    raw = build(
        aces=[ace(secdesc.ACCESS_ALLOWED_ACE, 0x08, 0x1, TRUSTEE_SID)]
    )

    descriptor = secdesc.parse(raw)
    entry = descriptor.dacl[0]
    assert isinstance(entry, secdesc.Ace)
    assert "INHERIT_ONLY_ACE" in secdesc.ace_flag_names(entry.flags)


def test_a_descriptor_without_a_dacl_has_no_aces() -> None:
    """A descriptor with no DACL has an empty one."""
    raw = build(aces=[])

    descriptor = secdesc.parse(raw)

    assert descriptor.dacl == ()


def test_a_descriptor_that_is_too_short_is_refused() -> None:
    """A buffer that is not a descriptor is refused."""
    with pytest.raises(secdesc.SecDescError):
        secdesc.parse(b"\x01\x00")


def test_a_descriptor_that_is_not_self_relative_is_refused() -> None:
    """Only the self-relative revision is read."""
    raw = build(aces=[])
    broken = bytes([2]) + raw[1:]

    with pytest.raises(secdesc.SecDescError):
        secdesc.parse(broken)


def test_an_offset_outside_the_descriptor_is_refused() -> None:
    """An offset that points nowhere is refused."""
    raw = bytearray(build(aces=[]))
    raw[4:8] = struct.pack("<I", 4096)

    with pytest.raises(secdesc.SecDescError):
        secdesc.parse(bytes(raw))


def test_a_sid_that_is_malformed_is_refused() -> None:
    """A SID whose length does not match its count is refused."""
    raw = bytearray(build(aces=[]))
    # The owner SID claims more sub-authorities than the buffer holds.
    raw[20 + 1] = 0xFF

    with pytest.raises(secdesc.SecDescError):
        secdesc.parse(bytes(raw))


def test_an_acl_that_is_truncated_is_refused() -> None:
    """An ACE that runs past the end of the buffer is refused."""
    raw = build(aces=[])
    broken = bytearray(raw)
    # The DACL claims one ACE that is not there.
    dacl_offset = struct.unpack("<I", bytes(raw[16:20]))[0]
    broken[dacl_offset + 4 : dacl_offset + 6] = struct.pack("<H", 1)

    with pytest.raises(secdesc.SecDescError):
        secdesc.parse(bytes(broken))


def test_an_acl_revision_that_is_not_known_is_refused() -> None:
    """Only the two documented ACL revisions are read."""
    raw = build(aces=[])
    broken = bytearray(raw)
    dacl_offset = struct.unpack("<I", bytes(raw[16:20]))[0]
    broken[dacl_offset] = 9

    with pytest.raises(secdesc.SecDescError):
        secdesc.parse(bytes(broken))


def test_the_rights_constants_are_the_documented_ones() -> None:
    """The rights the checks compare against are fixed."""
    assert secdesc.GENERIC_ALL == 0x10000000
    assert secdesc.ADS_RIGHT_GENERIC_ALL == 0x000F01FF
    assert secdesc.WRITE_DAC == 0x40000
    assert secdesc.WRITE_OWNER == 0x80000
    assert secdesc.ADS_RIGHT_DS_WRITE_PROP == 0x20
    assert secdesc.ADS_RIGHT_DS_CONTROL_ACCESS == 0x100
    assert secdesc.GENERIC_WRITE == 0x40000000


def test_the_error_message_never_carries_the_text_of_the_buffer() -> None:
    """A hostile descriptor does not get its text into the message."""
    raw = bytearray(build(aces=[]))
    raw[4:8] = struct.pack("<I", 4096)

    with pytest.raises(secdesc.SecDescError) as caught:
        secdesc.parse(bytes(raw))

    assert "4096" not in str(caught.value)


def test_the_ace_flags_of_an_unknown_flag_are_ignored() -> None:
    """A flag Newton does not name does not break the names."""
    names = secdesc.ace_flag_names(0x08 | 0x80)

    assert names == ("INHERIT_ONLY_ACE",)


def test_a_descriptor_round_trips_through_the_builder() -> None:
    """The builder and the reader agree on the layout."""
    raw = build(
        owner=OWNER_SID,
        group=GROUP_SID,
        aces=[
            ace(
                secdesc.ACCESS_ALLOWED_OBJECT_ACE,
                0x00,
                secdesc.GENERIC_ALL,
                TRUSTEE_SID,
                object_type=OBJECT_TYPE,
                inherited_object_type=INHERITED_TYPE,
            )
        ],
    )

    descriptor = secdesc.parse(raw)

    assert descriptor.owner == OWNER_SID
    assert descriptor.group == GROUP_SID
    entry = descriptor.dacl[0]
    assert isinstance(entry, secdesc.Ace)
    assert entry.mask == secdesc.GENERIC_ALL
    assert entry.trustee == TRUSTEE_SID


def test_the_ace_type_of_an_object_ace_is_read() -> None:
    """A denied object ACE is not an allowed one."""
    raw = build(
        aces=[
            ace(
                secdesc.ACCESS_DENIED_OBJECT_ACE,
                0x00,
                0x1,
                TRUSTEE_SID,
                object_type=OBJECT_TYPE,
                inherited_object_type=INHERITED_TYPE,
            )
        ]
    )

    descriptor = secdesc.parse(raw)
    entry = descriptor.dacl[0]
    assert isinstance(entry, secdesc.Ace)
    assert entry.type == secdesc.ACCESS_DENIED_OBJECT_ACE


def test_a_descriptor_that_is_not_bytes_is_refused() -> None:
    """The reader takes bytes."""
    with pytest.raises(secdesc.SecDescError):
        secdesc.parse("not bytes")  # type: ignore[arg-type]


def test_an_empty_buffer_is_refused() -> None:
    """An empty buffer is not a descriptor."""
    with pytest.raises(secdesc.SecDescError):
        secdesc.parse(b"")


def test_the_ace_helper_builds_the_size_of_the_ace() -> None:
    """The builder writes the size of the ACE it built."""
    built: Any = ace(secdesc.ACCESS_ALLOWED_ACE, 0, 0x1, TRUSTEE_SID)

    assert struct.unpack("<H", built[2:4])[0] == len(built)


def test_an_object_ace_with_one_type_reads_only_that_type() -> None:
    """Only the GUIDs whose bit is set are in the ACE."""
    raw = build(
        aces=[
            ace(
                secdesc.ACCESS_ALLOWED_OBJECT_ACE,
                0x00,
                0x100,
                TRUSTEE_SID,
                object_type=OBJECT_TYPE,
            )
        ]
    )

    descriptor = secdesc.parse(raw)

    entry = descriptor.dacl[0]
    assert isinstance(entry, secdesc.Ace)
    assert entry.object_type == OBJECT_TYPE
    assert entry.inherited_object_type is None
    assert entry.trustee == TRUSTEE_SID


def test_an_object_ace_without_a_type_still_has_its_trustee() -> None:
    """The trustee of an object ACE with no type is still the trustee."""
    raw = build(
        aces=[
            ace(
                secdesc.ACCESS_ALLOWED_OBJECT_ACE,
                0x00,
                0x100,
                TRUSTEE_SID,
            )
        ]
    )

    descriptor = secdesc.parse(raw)

    entry = descriptor.dacl[0]
    assert isinstance(entry, secdesc.Ace)
    assert entry.object_type is None
    assert entry.inherited_object_type is None
    assert entry.trustee == TRUSTEE_SID


def test_the_dcsync_ace_of_a_domain_head_is_read() -> None:
    """The ACE that names DS-Replication-Get-Changes is read as it is.

    It is the shape the domain head of a real directory carries: an
    object ACE whose object type is the replication right and whose
    trustee is a privileged group.
    """
    raw = build(
        aces=[
            ace(
                secdesc.ACCESS_ALLOWED_OBJECT_ACE,
                0x00,
                secdesc.ADS_RIGHT_DS_CONTROL_ACCESS,
                DOMAIN_ADMINS_SID,
                object_type=OBJECT_TYPE,
                inherited_object_type=GET_CHANGES_ALL,
            )
        ]
    )

    descriptor = secdesc.parse(raw)

    entry = descriptor.dacl[0]
    assert isinstance(entry, secdesc.Ace)
    assert entry.object_type == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    assert entry.inherited_object_type == GET_CHANGES_ALL
    assert entry.trustee == DOMAIN_ADMINS_SID
    assert entry.mask == secdesc.ADS_RIGHT_DS_CONTROL_ACCESS


def test_every_trustee_of_a_descriptor_is_a_sid() -> None:
    """Every trustee of a descriptor is a well-formed SID."""
    raw = build(
        aces=[
            ace(secdesc.ACCESS_ALLOWED_ACE, 0x00, 0x1F01FF, TRUSTEE_SID),
            ace(
                secdesc.ACCESS_DENIED_OBJECT_ACE,
                0x10,
                0x200,
                DOMAIN_ADMINS_SID,
                object_type=OBJECT_TYPE,
            ),
            ace(secdesc.ACCESS_ALLOWED_OBJECT_ACE, 0x00, 0x100, TRUSTEE_SID),
        ]
    )

    descriptor = secdesc.parse(raw)

    trustees = [entry.trustee for entry in descriptor.dacl]
    assert trustees == [
        TRUSTEE_SID,
        DOMAIN_ADMINS_SID,
        TRUSTEE_SID,
    ]


def test_a_descriptor_without_a_dacl_is_absent() -> None:
    """A descriptor whose control has no DACL bit has no DACL."""
    raw = build(aces=[], dacl_kind="absent")

    descriptor = secdesc.parse(raw)

    assert descriptor.dacl_state == "absent"
    assert descriptor.dacl == ()


def test_a_null_dacl_is_null() -> None:
    """A DACL that is present and has no offset is a null DACL."""
    raw = build(aces=[], dacl_kind="null")

    descriptor = secdesc.parse(raw)

    assert descriptor.dacl_state == "null"
    assert descriptor.dacl == ()


def test_an_empty_dacl_is_empty() -> None:
    """A DACL with no ACEs is an empty DACL, not a null one."""
    raw = build(aces=[], dacl_kind="present")

    descriptor = secdesc.parse(raw)

    assert descriptor.dacl_state == "empty"
    assert descriptor.dacl == ()


def test_a_dacl_with_aces_is_present() -> None:
    """A DACL with ACEs is a present DACL."""
    raw = build(
        aces=[ace(secdesc.ACCESS_ALLOWED_ACE, 0x00, 0x1, TRUSTEE_SID)]
    )

    descriptor = secdesc.parse(raw)

    assert descriptor.dacl_state == "present"


def test_a_null_dacl_is_everyone_full_control() -> None:
    """A null DACL lets everyone do everything."""
    raw = build(aces=[], dacl_kind="null")

    descriptor = secdesc.parse(raw)

    assert secdesc.everyone_has_full_control(descriptor) is True
    assert (
        secdesc.everyone_has_full_control(
            secdesc.parse(build(aces=[], dacl_kind="absent"))
        )
        is False
    )


def test_a_trustee_that_runs_past_its_ace_is_refused() -> None:
    """A SID that runs past the end of its ACE is malformed."""
    raw = bytearray(
        build(
            aces=[ace(secdesc.ACCESS_ALLOWED_ACE, 0x00, 0x1, TRUSTEE_SID)]
        )
    )
    # The trustee claims one sub-authority more than the ACE holds.
    dacl_offset = struct.unpack("<I", bytes(raw[16:20]))[0]
    sid_offset = dacl_offset + 8 + 4 + 4
    raw[sid_offset + 1] = 0xFF

    with pytest.raises(secdesc.SecDescError):
        secdesc.parse(bytes(raw))
