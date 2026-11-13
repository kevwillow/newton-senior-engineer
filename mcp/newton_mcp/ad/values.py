"""Decoders for the values a collector document carries.

A collector reports every value as a string (SPEC-1.3 section 5): a SID is
the base64 of the binary SID, a GUID is the base64 of the binary GUID, a
timestamp is either a GeneralizedTime string or a decimal int64.  This
module turns those into the canonical text the rest of the audit uses.

The decoders are total: they return the canonical value or raise
``ValueError`` with a fixed message.  They never echo the input, because the
input is directory-originated data and an error message reaches a log.

The binary layouts are the documented ones:

- a SID is a revision byte, a sub-authority count, a 48-bit big-endian
  identifier authority and little-endian 32-bit sub-authorities;
- a GUID is stored the way Windows stores it: the first three fields are
  little-endian, the last eight bytes are in order.

A SID in text has one canonical spelling: the revision and the authority
are decimal numbers, and so is every sub-authority, with no leading zero.
``canonical_sid`` parses a SID and prints it again, so two spellings of
one SID are one SID everywhere it is compared, and ``is_sid`` accepts a
text only when it is a SID whole.

The module also decodes the values of the domain that are not names: the
heuristics of the directory service, the functional levels, the trust
attributes and the timespans of the policy.

It also holds the tables the checks compare a directory value against:
the access mask of a directory ACE (MS-DTYP 2.4.6.2) with the stored
form of the generic rights, the schema GUIDs of the properties that
lead into the domain, and the extended rights that replicate it.  A
stored ACE never carries the GENERIC_* bits: it carries the rights
they expand to, so the table holds both forms.

``dn_key`` is the one key a distinguished name is indexed under: the name
is split into its RDNs, the escapes are decoded, the spaces around the
separators go and the whole name is lowercased.  ``dn_rdns`` is the same
name as the list of its RDNs: it is what a name is compared with when
one name is under another, because a suffix of the text of a name is
not a suffix of its RDNs (one RDN may hold an escaped comma).
``dn_display_name`` is the name a distinguished name reads as: the value
of its first RDN, with the escapes decoded, or the domain components of
the name joined with dots when the name is the name of a domain.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime, timedelta, timezone


# The epoch of a FILETIME: 1601-01-01 UTC, the Windows time origin.
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# The two FILETIME values that mean "never" (SPEC-1.3 section 4: a
# lastLogonTimestamp of 0 or 9223372036854775807 means the account has
# never logged on).  They are not timestamps and decode to None.
FILETIME_NEVER = 0
FILETIME_NEVER_MAX = 0x7FFFFFFFFFFFFFFF

# The largest value a signed 64-bit integer holds; a FILETIME above it is
# not a timestamp.
_INT64_MAX = 0x7FFFFFFFFFFFFFFF

# A GUID as text, the canonical lowercase form Windows prints.  The
# pattern is matched whole: a GUID that ends in a newline is not a GUID.
_GUID_TEXT_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

# One decimal number, ASCII digits only.
_NUMBER_RE = re.compile(r"[0-9]+")

# The most sub-authorities a SID can hold: the count is one byte.
MAX_SUB_AUTHORITIES = 15

# GeneralizedTime as the collectors write it: "YYYYMMDDHHMMSS.0Z".  The
# document example spells it "20261108T120000Z", so the "T" that RFC 4517
# puts between the date and the time is accepted but not required.
_GENTIME_RE = re.compile(
    r"^(\d{4})(\d{2})(\d{2})T?(\d{2})(\d{2})(\d{2})(?:\.(\d{1,6}))?Z$"
)

# The all-zero GUID: the object type of an object ACE that names no type.
ZERO_GUID = "00000000-0000-0000-0000-000000000000"


# The userAccountControl bits (MS-ADTS 2.2.6.1.1).  The table is the
# whole attribute: every named bit of the 32-bit value.  There is no
# bit of the value 0x400: the trust-account bits are 0x800 (interdomain
# trust), 0x1000 (workstation trust) and 0x2000 (server trust).
UAC_FLAGS: dict[int, str] = {
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

# The Kerberos encryption types of msDS-SupportedEncryptionTypes
# (MS-ADTS 6.1.4.4).  FAST_SUPPORTED is the armor bit, not a cipher,
# and 0x20 is the AES256 key of the service ticket.
ENC_TYPE_FLAGS: dict[int, str] = {
    0x00000001: "DES_CBC_CRC",
    0x00000002: "DES_CBC_MD5",
    0x00000004: "RC4",
    0x00000008: "AES128",
    0x00000010: "AES256",
    0x00000020: "AES256_SK",
    0x00010000: "FAST_SUPPORTED",
}

# The dSHeuristics positions Newton reads (MS-ADTS 7.1.1.2.4.1.2).  The
# attribute is a string of hex digits and every position holds the
# value of one heuristic.  The positions are 1-based: the first
# character of the attribute is position 1.
DS_HEURISTICS_LIST_OBJECT = 3
DS_HEURISTICS_BLOCK_ANONYMOUS_OPS = 7

# The dSHeuristics positions that carry the masks of the AdminSDHolder
# protection (MS-ADTS 7.1.1.2.4.1.2).  A dSHeuristics string that
# reaches position 10 carries the exclusion mask there, and one that
# reaches position 20 carries the second one; both are 1 in a domain
# that protects the objects the way Microsoft documents.
DS_HEURISTICS_ADMINSD_MASK = 10
DS_HEURISTICS_ADMINSD_EXCLUDE = 20

# The access mask of a directory ACE (MS-DTYP 2.4.6.2, MS-ADTS
# 6.1.1.2.4.1).  The bits Newton compares a stored ACE against.
ACCESS_MASK_CREATE_CHILD = 0x1
ACCESS_MASK_DELETE_CHILD = 0x2
ACCESS_MASK_LIST = 0x4
ACCESS_MASK_SELF = 0x8
ACCESS_MASK_READ_PROP = 0x10
ACCESS_MASK_WRITE_PROP = 0x20
ACCESS_MASK_DELETE_TREE = 0x40
ACCESS_MASK_LIST_OBJECT = 0x80
ACCESS_MASK_CONTROL_ACCESS = 0x100
ACCESS_MASK_DELETE = 0x10000
ACCESS_MASK_READ_CONTROL = 0x20000
ACCESS_MASK_WRITE_DAC = 0x40000
ACCESS_MASK_WRITE_OWNER = 0x80000
ACCESS_MASK_GENERIC_ALL = 0x10000000
ACCESS_MASK_GENERIC_WRITE = 0x40000000
ACCESS_MASK_GENERIC_READ = 0x80000000

# The stored form of the generic rights (MS-ADTS 6.1.1.2.4.1).  A
# stored ACE never carries the GENERIC_* bits: it carries the rights
# they expand to, so a check compares against these and never against
# the generic bit itself.
GENERIC_ALL_STORED = 0xF01FF
GENERIC_WRITE_STORED = 0x20028
GENERIC_READ_STORED = 0x20094

# The schema GUIDs of the properties a write on them is a way into the
# domain (SPEC-1.3 section 8, AD-A-52).
PROPERTY_GUIDS: dict[str, str] = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "member",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "servicePrincipalName",
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": "msDS-KeyCredentialLink",
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": (
        "msDS-AllowedToActOnBehalfOfOtherIdentity"
    ),
    "bf9679a8-0de6-11d0-a285-00aa003049e2": "scriptPath",
}

# The extended rights that let a principal replicate the directory
# (MS-ADTS 6.1.1.2.4.1, SPEC-1.3 section 8, AD-A-51).
EXTENDED_RIGHT_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
EXTENDED_RIGHT_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
EXTENDED_RIGHT_GET_CHANGES_IN_FILTERED_SET = (
    "89e95b76-444d-4c62-991a-0facbeda640c"
)

# The functional levels of a domain, of a configuration set and of the
# schema (MS-ADTS 6.1.1.1.4).  The value of msDS-Behavior-Version.
FUNCTIONAL_LEVELS: dict[int, str] = {
    0: "Windows 2000",
    1: "Windows XP",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016",
    8: "Windows Server 2019",
    9: "Windows Server 2022",
    10: "Windows Server 2025",
}

# The trust attributes of a trusted domain object (MS-ADTS 6.1.6.9).
TRUST_ATTRIBUTE_FLAGS: dict[int, str] = {
    0x00000001: "NON_TRANSITIVE",
    0x00000002: "UPLEVEL_ONLY",
    0x00000004: "QUARANTINED_DOMAIN",
    0x00000008: "FOREST_TRANSITIVE",
    0x00000010: "CROSS_ORGANIZATION",
    0x00000020: "WITHIN_FOREST",
    0x00000040: "TREAT_AS_EXTERNAL",
    0x00000080: "USES_RC4_ENCRYPTION",
}

# The trust attributes AD-A-48 judges (MS-ADTS 6.1.6.9).  The
# quarantined-domain attribute is the one that turns the SID filtering
# of a trust on: without it a principal of the trusted domain is
# treated as a principal of this one.
TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x00000001
TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x00000002
TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004
TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008
TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010
TRUST_ATTRIBUTE_WITHIN_FOREST = 0x00000020
TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040
TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 0x00000080

# One FILETIME tick is 100 nanoseconds; a timespan in the directory is
# counted in them.
HUNDRED_NANOSECONDS = 10_000_000


def sid_from_bytes(data: bytes) -> str:
    """Decode a binary SID into its canonical text form.

    The layout is the documented one: a revision byte, a sub-authority
    count, a 48-bit big-endian identifier authority and one little-endian
    32-bit sub-authority per count.
    """
    if len(data) < 8:
        raise ValueError("the sid blob is too short")
    revision = data[0]
    count = data[1]
    if len(data) != 8 + 4 * count:
        raise ValueError("the sid blob has the wrong length")
    authority = int.from_bytes(data[2:8], "big")
    parts = [f"S-{revision}", str(authority)]
    for index in range(count):
        start = 8 + 4 * index
        parts.append(str(int.from_bytes(data[start : start + 4], "little")))
    return "-".join(parts)


def sid_from_base64(text: str) -> str:
    """Decode a base64 SID blob into its canonical text form."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("the sid blob is not base64") from exc
    return sid_from_bytes(raw)


def canonical_sid(text: object) -> str:
    """The canonical text form of a SID.

    A SID is parsed and printed again, so two spellings of one SID are
    one SID: the printed form carries no leading zero in the revision,
    in the authority or in a sub-authority.  A sub-authority that is
    written with a leading zero is refused, because it is not the
    canonical number.  Anything that is not a SID raises ``ValueError``;
    the message never carries the input.
    """
    if not isinstance(text, str):
        raise ValueError("the sid is not text")
    parts = text.split("-")
    if len(parts) < 3 or parts[0] != "S":
        raise ValueError("the sid is not a sid")
    revision_text, authority_text = parts[1], parts[2]
    if not _NUMBER_RE.fullmatch(revision_text):
        raise ValueError("the sid revision is not a number")
    if not _NUMBER_RE.fullmatch(authority_text):
        raise ValueError("the sid authority is not a number")
    revision = int(revision_text)
    authority = int(authority_text)
    if revision > 255:
        raise ValueError("the sid revision is out of range")
    if authority > 0xFFFFFFFFFFFF:
        raise ValueError("the sid authority is out of range")
    sub_authorities: list[int] = []
    for part in parts[3:]:
        if not _NUMBER_RE.fullmatch(part):
            raise ValueError("a sid sub-authority is not a number")
        if len(part) > 1 and part.startswith("0"):
            raise ValueError("a sid sub-authority is not a canonical number")
        number = int(part)
        if number > 0xFFFFFFFF:
            raise ValueError("a sid sub-authority is out of range")
        sub_authorities.append(number)
    if len(sub_authorities) > MAX_SUB_AUTHORITIES:
        raise ValueError("the sid has too many sub-authorities")
    return "-".join(
        ["S", str(revision), str(authority)]
        + [str(number) for number in sub_authorities]
    )


def is_sid(text: object) -> bool:
    """True when the text is a well-formed SID."""
    try:
        canonical_sid(text)
    except ValueError:
        return False
    return True


def rid(sid: str) -> int | None:
    """The relative id of a SID, or None when the text is not a SID.

    The RID is the last component of the text form.  It is the only part
    of a SID that means something inside one domain, so a privileged check
    always compares the RID of a SID whose domain part is known.
    """
    if not isinstance(sid, str) or not is_sid(sid):
        return None
    return int(sid.rsplit("-", 1)[1])


def rid_in_domain(sid: str, domain_sid: str) -> int | None:
    """The RID of a SID inside one domain, or None when it is not one.

    A SID of another domain may carry the same last number, so the domain
    part has to match before the RID means anything.
    """
    if not isinstance(sid, str) or not isinstance(domain_sid, str):
        return None
    prefix = f"{domain_sid}-"
    if not sid.startswith(prefix):
        return None
    tail = sid[len(prefix) :]
    if not tail.isdigit():
        return None
    return int(tail)


def guid_from_bytes(data: bytes) -> str:
    """Decode a binary GUID into its canonical lowercase text form.

    Windows stores the first three fields little-endian and the last eight
    bytes in order; the text form prints them in that order, so the bytes
    are read the way Windows wrote them.
    """
    if len(data) != 16:
        raise ValueError("the guid blob is not 16 bytes")
    first = data[0:4][::-1].hex()
    second = data[4:6][::-1].hex()
    third = data[6:8][::-1].hex()
    rest = data[8:16].hex()
    return f"{first}-{second}-{third}-{rest[0:4]}-{rest[4:16]}"


def guid_from_base64(text: str) -> str:
    """Decode a base64 GUID blob into its canonical text form."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("the guid blob is not base64") from exc
    return guid_from_bytes(raw)


def is_guid(text: object) -> bool:
    """True when the text is a canonical lowercase GUID."""
    if not isinstance(text, str):
        return False
    return _GUID_TEXT_RE.fullmatch(text) is not None


# A pair of hex digits: the "\\XX" escape of a distinguished name.
_HEX_PAIR_RE = re.compile(r"[0-9a-fA-F]{2}")


def _split_unescaped(text: str, separator: str) -> list[str]:
    """The parts of a text, split on the separator that is not escaped.

    An escaped character is kept as it is written, so the part that
    holds it can still be decoded later.
    """
    parts: list[str] = []
    current: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            current.append(text[index : index + 2])
            index += 2
            continue
        if char == separator:
            parts.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    parts.append("".join(current))
    return parts


def _split_first_unescaped(text: str, separator: str) -> tuple[str, str, str]:
    """The text before the first unescaped separator, and the rest."""
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == separator:
            return text[:index], separator, text[index + 1 :]
        index += 1
    return text, "", ""


def _decode_hex_run(raw: bytes) -> str:
    """The bytes of a run of hex escapes, decoded as UTF-8.

    A "\\XX" escape of RFC 4514 is one byte of the UTF-8 encoding of
    the character it stands for, so a run of escapes is one run of
    bytes.  Bytes that are not valid UTF-8 become the replacement
    character: the name is read, not refused.
    """
    return raw.decode("utf-8", errors="replace")


def _unescape(text: str) -> str:
    """The text with the escapes of a distinguished name decoded.

    A "\\XX" pair of hex digits is one byte of the UTF-8 encoding, so
    the pairs that follow each other are collected into one run of
    bytes and decoded together; bytes that are not valid UTF-8 become
    the replacement character.  "\\X" is the character X.
    """
    out: list[str] = []
    pending: bytearray = bytearray()
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        escape = text[index + 1 : index + 3] if char == "\\" else ""
        if len(escape) == 2 and _HEX_PAIR_RE.fullmatch(escape):
            pending.append(int(escape, 16))
            index += 3
            continue
        if pending:
            out.append(_decode_hex_run(bytes(pending)))
            pending.clear()
        if char == "\\" and escape:
            out.append(escape[0])
            index += 2
            continue
        out.append(char)
        index += 1
    if pending:
        out.append(_decode_hex_run(bytes(pending)))
    return "".join(out)


def dn_rdns(dn: str) -> tuple[str, ...]:
    """The RDNs of a distinguished name, one normalised RDN each.

    The name is split on the commas that are not escaped, every RDN is
    normalised the way ``dn_key`` normalises it (the escapes are decoded,
    the spaces around the separators go and the RDN is lowercased) and
    the RDNs are returned in the order they are written in.  The list is
    what "is this name under that name" is decided on: the text of a
    name may end with the text of another one and still not be under it,
    because one RDN can hold an escaped comma.
    """
    if not isinstance(dn, str):
        return ()
    parts: list[str] = []
    for rdn in _split_unescaped(dn, ","):
        type_text, separator, value_text = _split_first_unescaped(rdn, "=")
        if not separator:
            parts.append(_unescape(rdn.strip()).lower())
            continue
        parts.append(
            f"{_unescape(type_text.strip()).lower()}="
            f"{_unescape(value_text.strip()).lower()}"
        )
    return tuple(parts)


def dn_key(dn: str) -> str:
    """The key a distinguished name is indexed under.

    A distinguished name is case-insensitive in a directory, so two names
    that differ only in case are one name.  The name is split into its
    RDNs, the escapes are decoded, the spaces around the separators go
    and the whole name is lowercased.  The one function every place
    that compares two names uses.
    """
    return ",".join(dn_rdns(dn))


def _rdn_parts(rdn: str) -> tuple[str, str]:
    """The type and the value of one RDN.

    The value is the text after the first unescaped ``=``: the RDN is
    not split again, so a value that holds an ``=`` is whole.
    """
    type_text, separator, value_text = _split_first_unescaped(rdn, "=")
    if not separator:
        return "", ""
    return _unescape(type_text.strip()), _unescape(value_text.strip())


def dn_display_name(dn: str) -> str | None:
    """The name a distinguished name reads as.

    The name of an object is the value of the first RDN of its
    distinguished name, with the escapes of RFC 4514 decoded: the
    escaped comma is a comma and the hex escapes are the bytes of the
    UTF-8 encoding of the text they stand for.  A name whose first RDN
    is a domain component reads as the domain: the components of the
    name joined with dots.

    A name that holds no RDN, or whose first RDN holds no value, has no
    display name.
    """
    if not isinstance(dn, str):
        return None
    rdns = _split_unescaped(dn, ",")
    if not rdns:
        return None
    first_type, first_value = _rdn_parts(rdns[0])
    if first_type.upper() == "DC":
        components: list[str] = []
        for rdn in rdns:
            rdn_type, rdn_value = _rdn_parts(rdn)
            if rdn_type.upper() != "DC":
                continue
            if not rdn_value:
                continue
            components.append(rdn_value)
        if not components:
            return None
        return ".".join(components)
    if not first_value:
        return None
    return first_value


def filetime_to_datetime(value: int) -> datetime | None:
    """Convert an int64 FILETIME into a UTC datetime.

    Zero and 0x7FFFFFFFFFFFFFFF mean "never" and return None.  Any other
    value that is not a positive int64 is not a timestamp and raises.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("the filetime is not an integer")
    if value in (FILETIME_NEVER, FILETIME_NEVER_MAX):
        return None
    if value <= 0 or value > _INT64_MAX:
        raise ValueError("the filetime is out of range")
    seconds, remainder = divmod(value, 10_000_000)
    # The remainder counts 100-nanosecond ticks inside the second.
    try:
        return FILETIME_EPOCH + timedelta(
            seconds=seconds, microseconds=remainder // 10
        )
    except OverflowError as exc:
        # A FILETIME no datetime can hold is not a timestamp.
        raise ValueError("the filetime is out of range") from exc


def parse_gentime(text: str) -> datetime:
    """Parse a GeneralizedTime string into a UTC datetime.

    The collectors write UTC (SPEC-1.3 section 5): "YYYYMMDDHHMMSS.0Z".
    A value without a fraction or with a different fraction length is
    accepted; anything else is refused.
    """
    if not isinstance(text, str):
        raise ValueError("the generalized time is not text")
    match = _GENTIME_RE.match(text)
    if match is None:
        raise ValueError("the generalized time is not in the expected form")
    fraction = match.group(7) or ""
    microsecond = int(fraction.ljust(6, "0")) if fraction else 0
    try:
        return datetime(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
            int(match.group(4)),
            int(match.group(5)),
            int(match.group(6)),
            microsecond,
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        raise ValueError("the generalized time is not a real time") from exc


def uac_flag_names(value: int) -> tuple[str, ...]:
    """The names of the userAccountControl bits that are set."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("the account control value is not an integer")
    return tuple(
        name for bit, name in sorted(UAC_FLAGS.items()) if value & bit
    )


def enc_type_flag_names(value: int) -> tuple[str, ...]:
    """The names of the Kerberos encryption types that are set."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("the encryption type value is not an integer")
    return tuple(
        name for bit, name in sorted(ENC_TYPE_FLAGS.items()) if value & bit
    )


def ds_heuristics_positions(text: str) -> dict[int, int]:
    """The dSHeuristics positions and the value each one holds.

    The attribute is a string of hex digits (MS-ADTS 7.1.1.2.4.1.2) and
    every position holds the value of one heuristic.  The positions are
    1-based, the way the specification counts them: the first character
    of the attribute is position 1, so the third character is position
    3.  The positions Newton does not know are in the result too: a
    heuristic it does not read is still a heuristic the domain set.

    The text is a directory-originated value, so an error message never
    carries it.
    """
    if not isinstance(text, str):
        raise ValueError("the heuristics are not text")
    positions: dict[int, int] = {}
    for index, char in enumerate(text, start=1):
        if char not in "0123456789abcdefABCDEF":
            raise ValueError("a heuristic is not a hex digit")
        positions[index] = int(char, 16)
    return positions


def functional_level_name(value: int) -> str:
    """The name of a functional level.

    A level this table does not hold is named by its number: an
    unknown level is a fact, not an error.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("the functional level is not an integer")
    return FUNCTIONAL_LEVELS.get(value, f"unknown level {value}")


def trust_attribute_names(value: int) -> tuple[str, ...]:
    """The names of the trust attributes that are set."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("the trust attribute value is not an integer")
    return tuple(
        name for bit, name in sorted(TRUST_ATTRIBUTE_FLAGS.items()) if value & bit
    )


def timespan_seconds(value: int) -> float:
    """A timespan of the directory in seconds.

    The directory counts a timespan in 100-nanosecond units and writes
    it with the sign of an interval, so a negative value is a span and
    not a time before the epoch.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("the timespan is not an integer")
    return abs(value) / HUNDRED_NANOSECONDS
