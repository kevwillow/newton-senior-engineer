"""Read a self-relative security descriptor (MS-DTYP 2.4.6).

The collectors ask for the owner and the DACL of a few objects and never
for the SACL, so this module reads the owner, the group and the DACL and
leaves the rest of the descriptor alone.

A descriptor is read defensively: every offset is checked against the
length of the buffer before it is used, and a descriptor that does not
make sense raises ``SecDescError`` instead of returning half a descriptor.
An ACE type this module does not know is kept as an ``UnknownAce`` and
never raises: a directory may hold ACE types Newton has not seen, and an
unknown ACE is still an ACE.

The four ACE types this module reads have two layouts.  The plain ones
are the header, the mask and the SID.  The object ones (MS-DTYP 2.4.4.3)
are the header, the mask, the four-byte flags that say which of the two
GUIDs are there, the GUIDs that are there and the SID: a GUID is in the
ACE only when its bit is set in those flags.

The DACL has four states and they are not the same thing: a DACL that the
control does not have is *absent*, a DACL that the control has and that
has no offset is *null* (everyone may do everything), a DACL with no ACEs
is *empty* and a DACL with ACEs is *present*.

The rights constants are the ones the checks compare against.
"""

from __future__ import annotations

from dataclasses import dataclass

from .values import guid_from_bytes, sid_from_bytes


# The rights the checks compare against.
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
ADS_RIGHT_GENERIC_ALL = 0x000F01FF
ADS_RIGHT_DS_WRITE_PROP = 0x20
ADS_RIGHT_DS_CONTROL_ACCESS = 0x100
WRITE_DAC = 0x40000
WRITE_OWNER = 0x80000

# The ACE types this module reads.
ACCESS_ALLOWED_ACE = 0x00
ACCESS_DENIED_ACE = 0x01
ACCESS_ALLOWED_OBJECT_ACE = 0x05
ACCESS_DENIED_OBJECT_ACE = 0x06

# The object ACE types carry two GUIDs.
OBJECT_ACE_TYPES = frozenset(
    {ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE}
)

# The flags of an object ACE (MS-DTYP 2.4.4.3): the four bytes after
# the mask say which of the two GUIDs are there.
ACE_OBJECT_TYPE_PRESENT = 0x00000001
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002

# The states a DACL can be in.
DACL_ABSENT = "absent"
DACL_NULL = "null"
DACL_EMPTY = "empty"
DACL_PRESENT = "present"

DACL_STATES = (DACL_ABSENT, DACL_NULL, DACL_EMPTY, DACL_PRESENT)

# The control bits of a descriptor (MS-DTYP 2.4.6).
SE_OWNER_DEFAULTED = 0x0001
SE_GROUP_DEFAULTED = 0x0002
SE_DACL_PRESENT = 0x0004
SE_DACL_DEFAULTED = 0x0008
SE_SACL_PRESENT = 0x0010
SE_SACL_DEFAULTED = 0x0020
SE_DACL_AUTO_INHERITED = 0x0400
SE_SACL_AUTO_INHERITED = 0x0800
SE_DACL_PROTECTED = 0x1000
SE_SACL_PROTECTED = 0x2000
SE_SELF_RELATIVE = 0x8000

# The ACL revisions that exist.
ACL_REVISION = 2
ACL_REVISION_DS = 4

# The flags of an ACE (MS-DTYP 2.4.4.1).
ACE_FLAGS: dict[int, str] = {
    0x01: "OBJECT_INHERIT_ACE",
    0x02: "CONTAINER_INHERIT_ACE",
    0x04: "NO_PROPAGATE_INHERIT_ACE",
    0x08: "INHERIT_ONLY_ACE",
    0x10: "INHERITED_ACE",
    0x20: "SUCCESSFUL_ACCESS_ACE",
    0x40: "FAILED_ACCESS_ACE",
}


class SecDescError(Exception):
    """The descriptor is not a descriptor Newton can read.

    The message never carries any text of the buffer.
    """


def _invalid(reason: str) -> SecDescError:
    return SecDescError(f"security descriptor invalid: {reason}")


@dataclass(frozen=True)
class UnknownAce:
    """An ACE of a type this module does not read."""

    type: int
    size: int


@dataclass(frozen=True)
class Ace:
    """One ACE of a DACL."""

    type: int
    flags: int
    mask: int
    object_type: str | None
    inherited_object_type: str | None
    trustee: str | None


@dataclass(frozen=True)
class SecurityDescriptor:
    """The owner, the group and the DACL of a descriptor."""

    revision: int
    control: int
    owner: str | None
    group: str | None
    dacl: tuple[Ace | UnknownAce, ...]
    dacl_state: str = DACL_PRESENT


def everyone_has_full_control(descriptor: SecurityDescriptor) -> bool:
    """True when the DACL is a null DACL.

    A null DACL grants everything to everyone: the object has no
    protection at all.  An absent DACL and an empty DACL are not the
    same thing, and neither of them is a null one.
    """
    return descriptor.dacl_state == DACL_NULL


def ace_flag_names(flags: int) -> tuple[str, ...]:
    """The names of the ACE flags that are set."""
    if not isinstance(flags, int) or isinstance(flags, bool) or flags < 0:
        raise ValueError("the ace flags are not an integer")
    return tuple(name for bit, name in sorted(ACE_FLAGS.items()) if flags & bit)


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise _invalid("an offset is outside the descriptor")
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise _invalid("an offset is outside the descriptor")
    return int.from_bytes(data[offset : offset + 4], "little")


def _read_sid(data: bytes, offset: int, end: int) -> tuple[str, int]:
    """The SID at an offset and the offset just after it.

    The SID may not run past ``end``: a trustee that runs past the end
    of its ACE is malformed, and a SID that runs past the end of the
    buffer is malformed too.
    """
    if offset < 0 or offset + 2 > end or end > len(data):
        raise _invalid("an offset is outside the descriptor")
    count = data[offset + 1]
    stop = offset + 8 + 4 * count
    if stop > end:
        raise _invalid("the sid is malformed")
    try:
        text = sid_from_bytes(data[offset:stop])
    except ValueError as exc:
        raise _invalid("the sid is malformed") from exc
    return text, stop


def _read_ace(data: bytes, offset: int) -> tuple[Ace | UnknownAce, int]:
    """The ACE at an offset and the offset just after it."""
    if offset < 0 or offset + 4 > len(data):
        raise _invalid("an offset is outside the descriptor")
    ace_type = data[offset]
    flags = data[offset + 1]
    size = _u16(data, offset + 2)
    if size < 4:
        raise _invalid("the ace is malformed")
    end = offset + size
    if end > len(data):
        raise _invalid("the ace is malformed")
    if ace_type not in (
        ACCESS_ALLOWED_ACE,
        ACCESS_DENIED_ACE,
        ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_DENIED_OBJECT_ACE,
    ):
        # An ACE of a type Newton does not read is still an ACE: it is
        # kept, and it never raises.
        return UnknownAce(type=ace_type, size=size), end

    body = offset + 4
    if body + 4 > end:
        raise _invalid("the ace is malformed")
    mask = _u32(data, body)
    cursor = body + 4
    object_type: str | None = None
    inherited_object_type: str | None = None
    if ace_type in OBJECT_ACE_TYPES:
        # MS-DTYP 2.4.4.3: the four bytes after the mask say which of
        # the two GUIDs are in this ACE, and only those are read.
        if cursor + 4 > end:
            raise _invalid("the ace is malformed")
        object_flags = _u32(data, cursor)
        cursor += 4
        if object_flags & ACE_OBJECT_TYPE_PRESENT:
            if cursor + 16 > end:
                raise _invalid("the ace is malformed")
            object_type = guid_from_bytes(data[cursor : cursor + 16])
            cursor += 16
        if object_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
            if cursor + 16 > end:
                raise _invalid("the ace is malformed")
            inherited_object_type = guid_from_bytes(data[cursor : cursor + 16])
            cursor += 16
    if cursor >= end:
        raise _invalid("the ace is malformed")
    trustee, _ = _read_sid(data, cursor, end)
    return (
        Ace(
            type=ace_type,
            flags=flags,
            mask=mask,
            object_type=object_type,
            inherited_object_type=inherited_object_type,
            trustee=trustee,
        ),
        end,
    )


def _read_acl(data: bytes, offset: int) -> tuple[Ace | UnknownAce, ...]:
    """The DACL at an offset."""
    if offset < 0 or offset + 8 > len(data):
        raise _invalid("an offset is outside the descriptor")
    revision = data[offset]
    if revision not in (ACL_REVISION, ACL_REVISION_DS):
        raise _invalid("the acl revision is not known")
    acl_size = _u16(data, offset + 2)
    ace_count = _u16(data, offset + 4)
    end = offset + acl_size
    if end > len(data):
        raise _invalid("the acl is malformed")
    cursor = offset + 8
    aces: list[Ace | UnknownAce] = []
    for _ in range(ace_count):
        if cursor >= end:
            raise _invalid("the acl is malformed")
        ace, cursor = _read_ace(data, cursor)
        aces.append(ace)
    return tuple(aces)


def parse(data: bytes) -> SecurityDescriptor:
    """Read a self-relative security descriptor."""
    if not isinstance(data, (bytes, bytearray)):
        raise _invalid("the descriptor is not bytes")
    raw = bytes(data)
    if len(raw) < 20:
        raise _invalid("the descriptor is too short")
    revision = raw[0]
    if revision != 1:
        raise _invalid("the descriptor is not self-relative")
    control = _u16(raw, 2)
    owner_offset = _u32(raw, 4)
    group_offset = _u32(raw, 8)
    dacl_offset = _u32(raw, 16)

    owner: str | None = None
    if owner_offset:
        owner, _ = _read_sid(raw, owner_offset, len(raw))
    group: str | None = None
    if group_offset:
        group, _ = _read_sid(raw, group_offset, len(raw))
    dacl: tuple[Ace | UnknownAce, ...] = ()
    if not control & SE_DACL_PRESENT:
        # The control says there is no DACL at all.
        dacl_state = DACL_ABSENT
    elif not dacl_offset:
        # The control says there is a DACL and there is none: a null
        # DACL, which grants everything to everyone.
        dacl_state = DACL_NULL
    else:
        dacl = _read_acl(raw, dacl_offset)
        dacl_state = DACL_EMPTY if not dacl else DACL_PRESENT

    return SecurityDescriptor(
        revision=revision,
        control=control,
        owner=owner,
        group=group,
        dacl=dacl,
        dacl_state=dacl_state,
    )
