"""The DNS data stored in the directory: dnsProperty, dnsRecord and node names.

The constants and the layouts here come from MS-DNSP (Windows Protocols,
Domain Name Service (DNS) Server Management Protocol), as published on
learn.microsoft.com and fetched on 2026-11-21.  The section numbers are in
the comments.  Nothing here was measured on a lab DC: the decoders read
what the spec says and refuse what it does not allow; they also refuse a
DNS label that is not ASCII, which the spec does allow (a fail-safe: the
check that needs the name says UNKNOWN).  A value they refuse makes the
check that needs it UNKNOWN.

Every decoder takes raw bytes and raises ``DnsDataError`` on a value that
is malformed; the message is fixed text and never carries the value,
because the value is device data.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable

from .values import dn_rdns


class DnsDataError(ValueError):
    """A DNS value of the directory is not what MS-DNSP says it is."""


# ---- dnsProperty (MS-DNSP 2.3.2.1) and its Ids (2.3.2.1.1) -------------------

# Property Ids, MS-DNSP 2.3.2.1.1 "Property Id".  The data of each is a DWORD.
DSPROPERTY_ZONE_TYPE = 0x00000001
DSPROPERTY_ZONE_ALLOW_UPDATE = 0x00000002
DSPROPERTY_ZONE_AGING_STATE = 0x00000040

# DNS_ZONE_TYPE, MS-DNSP 2.2.5.1.1.
DNS_ZONE_TYPE_PRIMARY = 0x01

# fAllowUpdate of DNS_RPC_ZONE_INFO_W2K, MS-DNSP 2.2.5.2.4.1.
ZONE_UPDATE_OFF = 0x00000000
ZONE_UPDATE_UNSECURE = 0x00000001
ZONE_UPDATE_SECURE = 0x00000002

# The layout of one dnsProperty value, MS-DNSP 2.3.2.1: DataLength,
# NameLength (not used), Flag (reserved), Version (MUST be 1), Id, each a
# 4-byte integer, then Data (DataLength bytes), then Name (1 byte, not
# used).  The spec does not state the byte order of these fields; the one
# field it marks big-endian is the TtlSeconds of dnsRecord, so the rest is
# read little-endian (see DESIGN-dns-helpers.md).
_PROPERTY_HEADER = struct.Struct("<IIIII")
_PROPERTY_NAME_BYTES = 1
_PROPERTY_VERSION = 1

# A property with DataLength 0 takes the default of its Id (2.3.2.1.1).
# The spec gives a default for the zone type (DNS_ZONE_TYPE_PRIMARY) and for
# the aging state (0), and none for the allow-update value, so an empty
# allow-update value is unreadable.
AGING_STATE_DEFAULT = 0


def decode_properties(values: Iterable[bytes]) -> dict[int, bytes]:
    """The dnsProperty values of a zone, as a map from Id to Data.

    An Id that appears twice is refused: the zone would have two answers.
    """
    found: dict[int, bytes] = {}
    for value in values:
        if len(value) < _PROPERTY_HEADER.size + _PROPERTY_NAME_BYTES:
            raise DnsDataError("a dnsProperty value is too short")
        data_length, _name_length, _flag, version, prop_id = _PROPERTY_HEADER.unpack_from(
            value
        )
        if version != _PROPERTY_VERSION:
            raise DnsDataError("a dnsProperty value has an unknown version")
        if len(value) != _PROPERTY_HEADER.size + data_length + _PROPERTY_NAME_BYTES:
            raise DnsDataError("a dnsProperty value has the wrong length")
        if prop_id in found:
            raise DnsDataError("a dnsProperty Id appears twice")
        start = _PROPERTY_HEADER.size
        found[prop_id] = bytes(value[start : start + data_length])
    return found


def property_dword(props: dict[int, bytes], prop_id: int) -> int | None:
    """The DWORD data of a property, or None when it is absent or empty.

    An empty value (DataLength 0) means "the default of the Id", which the
    caller applies when the spec gives one.  Any other size is refused.
    """
    data = props.get(prop_id)
    if data is None or data == b"":
        return None
    if len(data) != 4:
        raise DnsDataError("a dnsProperty DWORD has the wrong size")
    return struct.unpack("<I", data)[0]


# ---- dnsRecord (MS-DNSP 2.3.2.2) ---------------------------------------------

# DNS_RECORD_TYPE, MS-DNSP 2.2.2.1.1.
DNS_TYPE_SRV = 0x0021

# The layout of one dnsRecord value, MS-DNSP 2.3.2.2: DataLength (2),
# Type (2), Version (1, MUST be 5), Rank (1), Flags (2), Serial (4),
# TtlSeconds (4, big-endian), Reserved (4), TimeStamp (4), Data.  The
# fixed part is 24 bytes.
_RECORD_HEAD = struct.Struct("<HHBBHI")
_RECORD_FIXED = 24
_RECORD_VERSION = 5

# DNS_RPC_RECORD_SRV, MS-DNSP 2.2.2.2.4.18: wPriority, wWeight, wPort (2
# bytes each), then nameTarget.  The spec does not state the byte order of
# the three numbers, so they are skipped, never read.
_SRV_NUMBERS = 6


def count_name_text(raw: bytes) -> str:
    """The text of a DNS_COUNT_NAME, MS-DNSP 2.2.2.2.2.

    Length (1 byte: the size of RawName including the null), LabelCount
    (1 byte), RawName (a length byte before each label, null terminated).
    The empty name is Length 0 and LabelCount 0.
    """
    if len(raw) < 2:
        raise DnsDataError("a DNS name is too short")
    length, label_count = raw[0], raw[1]
    body = raw[2:]
    if len(body) != length:
        raise DnsDataError("a DNS name has the wrong length")
    if length == 0:
        if label_count != 0:
            raise DnsDataError("an empty DNS name has labels")
        return ""
    labels: list[str] = []
    index = 0
    while True:
        if index >= length:
            raise DnsDataError("a DNS name is not terminated")
        size = body[index]
        index += 1
        if size == 0:
            break
        if index + size > length:
            raise DnsDataError("a DNS label runs past the name")
        try:
            labels.append(body[index : index + size].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise DnsDataError("a DNS label is not ASCII") from exc
        index += size
    if index != length:
        raise DnsDataError("a DNS name has bytes after its end")
    if len(labels) != label_count:
        raise DnsDataError("a DNS name has the wrong label count")
    return ".".join(labels)


def srv_targets(values: Iterable[bytes]) -> list[str]:
    """The target host names of the SRV records among dnsRecord values.

    Records of another type are skipped (a node may hold several).  A
    target that is the empty name ("." in DNS terms) says the service is
    not available (RFC 2782): it is not a host, so it is skipped.  The
    names are lower-case without a trailing dot.
    """
    targets: list[str] = []
    for value in values:
        if len(value) < _RECORD_FIXED:
            raise DnsDataError("a dnsRecord value is too short")
        data_length, record_type, version, _rank, _flags, _serial = _RECORD_HEAD.unpack_from(
            value
        )
        if version != _RECORD_VERSION:
            raise DnsDataError("a dnsRecord value has an unknown version")
        if len(value) != _RECORD_FIXED + data_length:
            raise DnsDataError("a dnsRecord value has the wrong length")
        if record_type != DNS_TYPE_SRV:
            continue
        data = value[_RECORD_FIXED:]
        if len(data) < _SRV_NUMBERS + 2:
            raise DnsDataError("an SRV record is too short")
        name = count_name_text(bytes(data[_SRV_NUMBERS:]))
        if not name:
            continue
        targets.append(name.rstrip(".").lower())
    return targets


# ---- the name of a node ------------------------------------------------------

# The containers a zone lives in: CN=MicrosoftDNS in a DNS application
# partition (the domain's or the forest's).
_ZONE_CONTAINER = "cn=microsoftdns"
_PARTITIONS = ("dc=domaindnszones", "dc=forestdnszones")


def node_name(dn: str) -> str | None:
    """The DNS name of a zone or a node, from its distinguished name.

    ``DC=_ldap,DC=_tcp,DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,...``
    is ``_ldap._tcp.corp.example``: the RDNs before ``CN=MicrosoftDNS`` are
    the labels (one RDN is the zone, whose value is its dotted name), left
    to right.  The one-label-per-RDN layout is what a DC does in practice
    and is not in MS-DNSP; a dotted RDN is read the same way.  A name that
    is not under a DNS application partition (the legacy container in
    CN=System, any other place) is None.
    """
    rdns = dn_rdns(dn)
    for index, rdn in enumerate(rdns):
        if rdn == _ZONE_CONTAINER:
            break
    else:
        return None
    if index == 0 or index + 1 >= len(rdns) or rdns[index + 1] not in _PARTITIONS:
        return None
    labels: list[str] = []
    for rdn in rdns[:index]:
        kind, _, value = rdn.partition("=")
        if kind != "dc" or not value:
            return None
        labels.append(value)
    return ".".join(labels)
