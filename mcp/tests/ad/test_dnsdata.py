"""The decoders of the DNS data of the directory (spec-derived, unmeasured).

The encodings come from MS-DNSP (see dns_spec.py), so these tests prove
that Newton reads what the spec says and refuses what the spec does not
allow.  They are not a measurement of a lab DC.
"""

from __future__ import annotations

import base64
import struct

import pytest

import dns_spec as spec
from newton_mcp.ad import dnsdata


def _raw(values: list[str]) -> list[bytes]:
    return [base64.b64decode(value) for value in values]


def test_the_constants_are_the_ones_of_ms_dnsp() -> None:
    assert dnsdata.DSPROPERTY_ZONE_TYPE == 0x00000001
    assert dnsdata.DSPROPERTY_ZONE_ALLOW_UPDATE == 0x00000002
    assert dnsdata.DSPROPERTY_ZONE_AGING_STATE == 0x00000040
    assert dnsdata.DNS_ZONE_TYPE_PRIMARY == 0x01
    assert dnsdata.ZONE_UPDATE_OFF == 0
    assert dnsdata.ZONE_UPDATE_UNSECURE == 1
    assert dnsdata.ZONE_UPDATE_SECURE == 2
    assert dnsdata.DNS_TYPE_SRV == 0x0021


def test_properties_are_read_by_id() -> None:
    props = dnsdata.decode_properties(
        _raw(spec.zone_properties(allow_update=spec.UPDATE_UNSECURE, aging=0))
    )

    assert dnsdata.property_dword(props, dnsdata.DSPROPERTY_ZONE_TYPE) == 1
    assert dnsdata.property_dword(props, dnsdata.DSPROPERTY_ZONE_ALLOW_UPDATE) == 1
    assert dnsdata.property_dword(props, dnsdata.DSPROPERTY_ZONE_AGING_STATE) == 0


def test_an_absent_property_is_none_and_a_zero_length_one_is_the_default() -> None:
    props = dnsdata.decode_properties(
        _raw(spec.zone_properties(aging=None))
        + [spec.dns_property(spec.ID_AGING_STATE, b"")]
    )

    assert dnsdata.property_dword(props, 0x1234) is None
    assert props[dnsdata.DSPROPERTY_ZONE_AGING_STATE] == b""
    assert dnsdata.property_dword(props, dnsdata.DSPROPERTY_ZONE_AGING_STATE) is None


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"\x00" * 10,
        spec.dns_property(spec.ID_ALLOW_UPDATE, b"\x01\x00\x00\x00")[:-1],  # no name byte
        spec.dns_property(spec.ID_ALLOW_UPDATE, b"\x01\x00\x00\x00") + b"\x00",  # trailing byte
        spec.dns_property(spec.ID_ALLOW_UPDATE, b"\x01\x00\x00\x00", version=2),
        struct.pack("<IIIII", 0xFFFFFFFF, 1, 0, 1, 2) + b"\x00",  # length past the value
    ],
)
def test_a_malformed_property_is_refused(bad: bytes) -> None:
    with pytest.raises(dnsdata.DnsDataError):
        dnsdata.decode_properties([bad])


def test_a_dword_property_of_the_wrong_size_is_refused() -> None:
    props = dnsdata.decode_properties(
        [spec.dns_property(spec.ID_ALLOW_UPDATE, b"\x01\x00")]
    )

    with pytest.raises(dnsdata.DnsDataError):
        dnsdata.property_dword(props, dnsdata.DSPROPERTY_ZONE_ALLOW_UPDATE)


def test_the_same_property_twice_is_refused() -> None:
    one = spec.dword_property(spec.ID_ALLOW_UPDATE, 2)

    with pytest.raises(dnsdata.DnsDataError):
        dnsdata.decode_properties([one, one])


def test_count_name_round_trips() -> None:
    assert dnsdata.count_name_text(spec.count_name("dc1.corp.example.test")) == "dc1.corp.example.test"
    assert dnsdata.count_name_text(spec.count_name("")) == ""


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"\x05\x01\x03abc",  # Length says 5, RawName is 4 bytes
        b"\x04\x01\x03abc",  # not null terminated
        b"\x05\x02\x03abc\x00",  # LabelCount says 2, there is 1
        b"\x05\x01\x09abc\x00",  # a label longer than what is left
        b"\x07\x01\x03abc\x00xx",  # bytes after the name
    ],
)
def test_a_malformed_count_name_is_refused(bad: bytes) -> None:
    with pytest.raises(dnsdata.DnsDataError):
        dnsdata.count_name_text(bad)


def test_srv_targets_are_read_and_other_record_types_are_skipped() -> None:
    values = _raw(
        [
            spec.srv_record("dc1.corp.example.test"),
            spec.a_record("192.0.2.5"),
            spec.srv_record("DC2.corp.example.test."),
        ]
    )

    assert dnsdata.srv_targets(values) == ["dc1.corp.example.test", "dc2.corp.example.test"]


def test_the_empty_target_is_not_a_host() -> None:
    """RFC 2782: the target "." says the service is not available."""
    values = _raw([spec.srv_record("")])

    assert dnsdata.srv_targets(values) == []


def test_a_truncated_srv_record_is_refused() -> None:
    good = base64.b64decode(spec.srv_record("dc1.corp.example.test"))

    with pytest.raises(dnsdata.DnsDataError):
        dnsdata.srv_targets([good[:-3]])
    with pytest.raises(dnsdata.DnsDataError):
        dnsdata.srv_targets([good[:10]])


def test_a_record_whose_length_does_not_match_is_refused() -> None:
    good = bytearray(base64.b64decode(spec.srv_record("dc1.corp.example.test")))
    good[0] = (good[0] + 1) & 0xFF

    with pytest.raises(dnsdata.DnsDataError):
        dnsdata.srv_targets([bytes(good)])


def test_node_name_is_built_from_the_dn_of_the_node() -> None:
    dn = "DC=_ldap,DC=_tcp,DC=corp.example.test,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example,DC=test"

    assert dnsdata.node_name(dn) == "_ldap._tcp.corp.example.test"


def test_node_name_copes_with_a_dotted_rdn_and_refuses_a_foreign_dn() -> None:
    dotted = "DC=_ldap._tcp,DC=corp.example.test,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example,DC=test"

    assert dnsdata.node_name(dotted) == "_ldap._tcp.corp.example.test"
    assert dnsdata.node_name("CN=x,DC=corp,DC=example,DC=test") is None
    assert dnsdata.node_name("DC=a,CN=MicrosoftDNS,CN=System,DC=corp,DC=test") is None
