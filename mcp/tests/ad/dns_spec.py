"""Spec-derived DNS encodings for the tests (NOT measured on a lab DC).

Every byte here is built from the structures of MS-DNSP as published on
learn.microsoft.com (fetched 2026-11-21), and each builder names the
section it follows.  No lab DC was read: a real DC may differ in a way the
spec does not say (the byte order of the dnsProperty fields, the layout of
the nodes under a zone), and the design note lists those as unmeasured.
These helpers make fixtures that are *spec-derived*, never *measured*.
"""

from __future__ import annotations

import base64
import struct

# MS-DNSP 2.3.2.1.1 (Property Id) and 2.2.5.2.4.1 (the values).
ID_ZONE_TYPE = 0x00000001
ID_ALLOW_UPDATE = 0x00000002
ID_AGING_STATE = 0x00000040
ZONE_TYPE_PRIMARY = 1
ZONE_TYPE_SECONDARY = 2
UPDATE_OFF, UPDATE_UNSECURE, UPDATE_SECURE = 0, 1, 2

# MS-DNSP 2.2.2.1.1 (DNS_RECORD_TYPE).
TYPE_A = 0x0001
TYPE_SRV = 0x0021


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def dns_property(prop_id: int, data: bytes, *, version: int = 1) -> bytes:
    """One dnsProperty value, MS-DNSP 2.3.2.1.

    DataLength, NameLength (1), Flag (0), Version (1), Id, Data, Name (1
    byte), every integer little-endian (the spec does not say; see the
    design note).
    """
    return struct.pack("<IIIII", len(data), 1, 0, version, prop_id) + data + b"\x00"


def dword_property(prop_id: int, value: int) -> bytes:
    return dns_property(prop_id, struct.pack("<I", value))


def zone_properties(
    *,
    zone_type: int | None = ZONE_TYPE_PRIMARY,
    allow_update: int | None = UPDATE_SECURE,
    aging: int | None = 1,
) -> list[str]:
    """The dNSProperty values of a zone, base64, as a row carries them."""
    values: list[bytes] = []
    if zone_type is not None:
        values.append(dword_property(ID_ZONE_TYPE, zone_type))
    if allow_update is not None:
        values.append(dword_property(ID_ALLOW_UPDATE, allow_update))
    if aging is not None:
        values.append(dword_property(ID_AGING_STATE, aging))
    return [b64(value) for value in values]


def count_name(fqdn: str) -> bytes:
    """A DNS_COUNT_NAME, MS-DNSP 2.2.2.2.2.

    Length (RawName bytes including the null), LabelCount, RawName (a
    length byte before each label, null terminated).
    """
    if not fqdn:
        return b"\x00\x00"
    labels = fqdn.rstrip(".").split(".")
    raw = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return bytes([len(raw), len(labels)]) + raw


def dns_record(record_type: int, data: bytes, *, ttl: int = 600) -> bytes:
    """One dnsRecord value, MS-DNSP 2.3.2.2.

    DataLength u16, Type u16, Version u8 (5), Rank u8, Flags u16, Serial
    u32, TtlSeconds u32 (big-endian), Reserved u32, TimeStamp u32, Data.
    """
    return (
        struct.pack("<HHBBHI", len(data), record_type, 5, 0xF0, 0, 1)
        + struct.pack(">I", ttl)
        + struct.pack("<II", 0, 0)
        + data
    )


def srv_record(target: str, *, priority: int = 0, weight: int = 100, port: int = 389) -> str:
    """A dnsRecord value for an SRV record (2.2.2.2.4.18), base64."""
    data = struct.pack(">HHH", priority, weight, port) + count_name(target)
    return b64(dns_record(TYPE_SRV, data))


def a_record(address: str) -> str:
    """A dnsRecord value for an A record, base64 (not an SRV: it is skipped)."""
    data = bytes(int(part) for part in address.split("."))
    return b64(dns_record(TYPE_A, data))


def with_healthy_dns(document: dict) -> dict:
    """A copy of a measured document with spec-derived healthy DNS rows.

    The measured documents carry the three DNS queries as ``not_collected``
    (they were never measured).  Tests that need those queries to hold data
    use this: one writable DC, its ``_ldap._tcp`` SRV record and two secure
    zones, all built from the spec encodings.  The data is NOT measured.
    """
    import copy

    out = copy.deepcopy(document)
    dns = out["domain"]["dns"]
    root = out["domain"]["domain_dn"]
    container = f"CN=MicrosoftDNS,DC=DomainDnsZones,{root}"

    def zone(name: str) -> dict:
        dn = f"DC={name},{container}"
        return {"dn": dn, "a": {"distinguishedName": [dn], "dNSProperty": zone_properties()}}

    node_dn = f"DC=_ldap,DC=_tcp,DC={dns},{container}"
    dc_dn = f"CN=DC1,OU=Domain Controllers,{root}"
    ok = {"status": "ok", "error_code": ""}
    out["queries"]["dns_zones"] = {**ok, "rows": [zone(dns), zone(f"_msdcs.{dns}")]}
    out["queries"]["dns_ldap_srv"] = {
        **ok,
        "rows": [
            {
                "dn": node_dn,
                "a": {"distinguishedName": [node_dn], "dnsRecord": [srv_record(f"dc1.{dns}")]},
            }
        ],
    }
    out["queries"]["dc_hosts"] = {
        **ok,
        "rows": [
            {
                "dn": dc_dn,
                "a": {
                    "distinguishedName": [dc_dn],
                    "dNSHostName": [f"dc1.{dns}"],
                    "primaryGroupID": ["516"],
                },
            }
        ],
    }
    return out
