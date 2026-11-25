"""The DNS checks: zones and the DC SRV records.

Covered by tests only, unmeasured on a lab DC (DESIGN-dns-helpers.md).
The constants and the encodings are MS-DNSP's (see ``..dnsdata``); the
layout of the nodes under a zone and the rights of the audit account on
the DNS objects are what a lab measurement still has to confirm.

Four checks, ids from the GAPS rows AD-A-68 (DNS posture) and AD-A-69
(stale DC records):

- AD-A-68a a zone allows non-secure dynamic updates;
- AD-A-68b a zone that takes dynamic updates has aging off;
- AD-A-69a a domain controller has no ``_ldap._tcp.<domain>`` SRV record;
- AD-A-69b that SRV record names a host that is not a domain controller.

Left out on purpose (design note): zone transfers and forwarders.  MS-DNSP
stores neither in the dnsZone object, so the read account cannot see them.

A value that cannot be read (a property that is missing, an encoding the
spec does not allow) makes the check UNKNOWN, never PASS.  Zone names,
host names and distinguished names are directory data: they are only put
in ``Affected`` (the renderer envelopes them) and never in a note or a
fix, which carry counts and fixed text.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable

from ..catalogue import Check
from ..dnsdata import (
    AGING_STATE_DEFAULT,
    DNS_ZONE_TYPE_PRIMARY,
    DSPROPERTY_ZONE_AGING_STATE,
    DSPROPERTY_ZONE_ALLOW_UPDATE,
    DSPROPERTY_ZONE_TYPE,
    ZONE_UPDATE_OFF,
    ZONE_UPDATE_SECURE,
    ZONE_UPDATE_UNSECURE,
    DnsDataError,
    decode_properties,
    node_name,
    property_dword,
    srv_targets,
)
from ..model import (
    Affected,
    CheckResult,
    Finding,
    Fix,
    FixStep,
    Severity,
    Status,
    UnknownReason,
)
from ..wire import Document, Row
from .domain import Spec, _make, _number, _result, _rows, _text

# The primaryGroupID of a domain controller and of a read-only one.
PRIMARY_GROUP_DC = 516
PRIMARY_GROUP_RODC = 521


def _fix(summary_windows: str, summary_samba: str, changes: str, revert: str) -> Fix:
    return Fix(
        windows=FixStep(summary=summary_windows, commands=(), changes=changes, revert=revert),
        samba=FixStep(summary=summary_samba, commands=(), changes=changes, revert=revert),
    )


_SPEC_68A = Spec(
    id="AD-A-68a",
    title="DNS zones that accept non-secure dynamic updates",
    severity=Severity.HIGH,
    maps_to=("MS DNS",),
    fix=_fix(
        "Set the dynamic update setting of each zone named in the envelope to secure only "
        "(DNS Manager, zone properties, General; or the DnsServer module).",
        "Set the dynamic update setting of each zone named in the envelope to secure only "
        "with the DNS tooling of your Samba version (samba-tool dns zoneoptions).",
        "the dynamic update setting of each affected zone",
        "set the zone back to the dynamic update value it had before the change",
    ),
)

_SPEC_68B = Spec(
    id="AD-A-68b",
    title="DNS zones with dynamic updates and aging off",
    severity=Severity.LOW,
    maps_to=("MS DNS",),
    fix=_fix(
        "Turn on aging for each zone named in the envelope, and confirm a DNS server "
        "scavenges the zone (DNS Manager, zone properties, Aging).",
        "Turn on aging for each zone named in the envelope with the DNS tooling of your "
        "Samba version, and confirm a DNS server scavenges the zone.",
        "the aging setting of each affected zone",
        "turn aging off again for the zone",
    ),
)

_SPEC_69A = Spec(
    id="AD-A-69a",
    title="Domain controllers missing from the domain SRV record",
    severity=Severity.MEDIUM,
    maps_to=("MS Recovery/Replication",),
    fix=_fix(
        "On the domain controller named in the envelope, restart the Netlogon service "
        "(it re-registers its records) and check that DNS accepts the update.",
        "On the domain controller named in the envelope, run the DNS update of the "
        "Samba tooling (samba_dnsupdate) and check that DNS accepts the update.",
        "the SRV records the domain controller registers in DNS",
        "remove the records the controller registered, if it should not be listed",
    ),
)

_SPEC_69B = Spec(
    id="AD-A-69b",
    title="Stale domain SRV record for a host that is not a domain controller",
    severity=Severity.MEDIUM,
    maps_to=("MS Recovery/Replication",),
    fix=_fix(
        "Check the host named in the envelope. If it is a demoted or deleted controller, "
        "clean up its metadata and delete its stale SRV records in DNS Manager.",
        "Check the host named in the envelope. If it is a demoted or deleted controller, "
        "clean up its metadata and delete its stale records with samba-tool dns delete.",
        "the stale SRV records of the host",
        "add the same SRV record again if the host is still a controller",
    ),
)


# ---- reading the rows -------------------------------------------------------


def _raw_values(row: Row, name: str) -> list[bytes] | None:
    """The decoded bytes of a binary attribute, or None when the row lacks it."""
    values = row.a.get(name)
    if not values:
        return None
    try:
        return [base64.b64decode(value, validate=True) for value in values]
    except (binascii.Error, ValueError):
        raise DnsDataError("a binary attribute is not base64") from None


class _Zone:
    """The properties of one primary zone that the checks read."""

    def __init__(self, row: Row) -> None:
        self.row = row
        raw = _raw_values(row, "dNSProperty")
        if raw is None:
            raise DnsDataError("a zone has no dNSProperty")
        props = decode_properties(raw)
        if DSPROPERTY_ZONE_TYPE not in props:
            raise DnsDataError("a zone has no type")
        zone_type = property_dword(props, DSPROPERTY_ZONE_TYPE)
        if zone_type is None:
            # DataLength 0 takes the default of the Id (MS-DNSP 2.3.2.1.1):
            # DNS_ZONE_TYPE_PRIMARY.
            zone_type = DNS_ZONE_TYPE_PRIMARY
        self.primary = zone_type == DNS_ZONE_TYPE_PRIMARY
        self.allow_update: int | None = None
        self.aging: int | None = None
        if not self.primary:
            return
        update = property_dword(props, DSPROPERTY_ZONE_ALLOW_UPDATE)
        if update not in (ZONE_UPDATE_OFF, ZONE_UPDATE_UNSECURE, ZONE_UPDATE_SECURE):
            raise DnsDataError("a zone has no readable update setting")
        self.allow_update = update
        if DSPROPERTY_ZONE_AGING_STATE in props:
            aging = property_dword(props, DSPROPERTY_ZONE_AGING_STATE)
            # DataLength 0 takes the default of the Id (MS-DNSP 2.3.2.1.1).
            self.aging = AGING_STATE_DEFAULT if aging is None else aging

    @property
    def takes_updates(self) -> bool:
        return self.allow_update in (ZONE_UPDATE_UNSECURE, ZONE_UPDATE_SECURE)


def _zones(document: Document) -> tuple[list[_Zone], int]:
    """The zones that could be read, and the number that could not."""
    zones: list[_Zone] = []
    unreadable = 0
    for row in _rows(document, "dns_zones"):
        try:
            zones.append(_Zone(row))
        except DnsDataError:
            unreadable += 1
    return zones, unreadable


def _zone_note(read: int, skipped: int, unreadable: int) -> str:
    parts = [f"{read} zone(s) read"]
    if skipped:
        parts.append(f"{skipped} zone(s) not primary and not judged")
    if unreadable:
        parts.append(f"{unreadable} zone(s) could not be read")
    return "; ".join(parts)


def _finish(
    spec: Spec,
    findings: list[Finding],
    unreadable: int,
    note: str,
) -> CheckResult:
    if findings:
        return _result(spec, Status.FINDING, note=note, findings=tuple(findings))
    if unreadable:
        return _result(
            spec, Status.UNKNOWN, reason=UnknownReason.PARSE_REFUSED, note=note
        )
    return _result(spec, Status.PASS, note=note)


def _finding(spec: Spec, affected: Affected, title: str) -> Finding:
    return Finding(
        check_id=spec.id,
        severity=spec.severity,
        title=title,
        objects=(affected,),
        maps_to=spec.maps_to,
        fix=spec.fix,
    )


# ---- AD-A-68a and AD-A-68b ---------------------------------------------------


def _evaluate_68a(document: Document, spec: Spec) -> CheckResult:
    zones, unreadable = _zones(document)
    primary = [zone for zone in zones if zone.primary]
    findings = [
        _finding(
            spec,
            Affected(
                dn=zone.row.dn,
                evidence="dynamic updates: secure and non-secure",
            ),
            "A DNS zone accepts non-secure dynamic updates",
        )
        for zone in primary
        if zone.allow_update == ZONE_UPDATE_UNSECURE
    ]
    note = _zone_note(len(primary), len(zones) - len(primary), unreadable)
    return _finish(spec, findings, unreadable, note)


def _evaluate_68b(document: Document, spec: Spec) -> CheckResult:
    zones, unreadable = _zones(document)
    primary = [zone for zone in zones if zone.primary]
    findings: list[Finding] = []
    for zone in primary:
        # fAging, MS-DNSP 2.2.5.2.4.1: TRUE 1 or FALSE 0, no other value.
        # A value the spec does not allow makes this zone unreadable for
        # this check only: AD-A-68a does not read the aging value.
        if zone.aging is not None and zone.aging not in (0, 1):
            unreadable += 1
            continue
        if not zone.takes_updates:
            continue
        if zone.aging is None:
            unreadable += 1
        elif zone.aging == 0:
            findings.append(
                _finding(
                    spec,
                    Affected(
                        dn=zone.row.dn,
                        evidence="aging is off while dynamic updates are on",
                    ),
                    "A DNS zone with dynamic updates has aging off",
                )
            )
    note = (
        _zone_note(len(primary), len(zones) - len(primary), unreadable)
        + "; scavenging is a server setting and is not read"
    )
    return _finish(spec, findings, unreadable, note)


# ---- AD-A-69a and AD-A-69b ---------------------------------------------------


class _SrvView:
    """The SRV targets of the domain and the domain controllers of the directory."""

    def __init__(self, document: Document) -> None:
        self.domain = document.domain.dns.lower()
        wanted = f"_ldap._tcp.{self.domain}"
        nodes = [
            row for row in _rows(document, "dns_ldap_srv") if node_name(row.dn) == wanted
        ]
        self.node_dn = nodes[0].dn if nodes else None
        self.found_node = bool(nodes)
        self.targets: set[str] = set()
        for node in nodes:
            raw = _raw_values(node, "dnsRecord")
            if raw is None:
                raise DnsDataError("the SRV node has no dnsRecord")
            self.targets.update(srv_targets(raw))
        self.writable: list[tuple[Row, str]] = []
        self.all_hosts: set[str] = set()
        for row in _rows(document, "dc_hosts"):
            group = _number(row, "primaryGroupID")
            if group not in (PRIMARY_GROUP_DC, PRIMARY_GROUP_RODC):
                continue
            host = _text(row, "dNSHostName")
            if not host:
                raise DnsDataError("a domain controller has no dNSHostName")
            host = host.rstrip(".").lower()
            self.all_hosts.add(host)
            if group == PRIMARY_GROUP_DC:
                self.writable.append((row, host))


def _srv_view(spec: Spec, document: Document) -> _SrvView | CheckResult:
    try:
        view = _SrvView(document)
    except DnsDataError:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.PARSE_REFUSED,
            note="a DNS record or a domain controller object could not be read",
        )
    if not view.found_node:
        return _result(
            spec,
            Status.UNKNOWN,
            reason=UnknownReason.UNAVAILABLE,
            note="the _ldap._tcp node of the domain zone was not found in the DNS partition",
        )
    return view


def _evaluate_69a(document: Document, spec: Spec) -> CheckResult:
    view = _srv_view(spec, document)
    if isinstance(view, CheckResult):
        return view
    findings = [
        _finding(
            spec,
            Affected(
                dn=row.dn,
                name=host,
                evidence=f"no SRV record of _ldap._tcp.{view.domain} points at this controller",
            ),
            "A domain controller is missing from the domain SRV record",
        )
        for row, host in view.writable
        if host not in view.targets
    ]
    note = f"{len(view.writable)} domain controller(s) and {len(view.targets)} SRV target(s) read"
    return _finish(spec, findings, 0, note)


def _evaluate_69b(document: Document, spec: Spec) -> CheckResult:
    view = _srv_view(spec, document)
    if isinstance(view, CheckResult):
        return view
    findings = [
        _finding(
            spec,
            Affected(
                dn=view.node_dn,
                name=target,
                evidence=(
                    f"an SRV record of _ldap._tcp.{view.domain} points at a host "
                    "that is not a domain controller of this domain"
                ),
            ),
            "A domain SRV record points at a host that is not a domain controller",
        )
        for target in sorted(view.targets - view.all_hosts)
    ]
    note = f"{len(view.all_hosts)} domain controller(s) and {len(view.targets)} SRV target(s) read"
    return _finish(spec, findings, 0, note)


CHECKS: list[Check] = [
    _make(
        _SPEC_68A,
        _evaluate_68a,
        queries=("dns_zones",),
        sentinels=("dns_zones",),
    ),
    _make(
        _SPEC_68B,
        _evaluate_68b,
        queries=("dns_zones",),
        sentinels=("dns_zones",),
    ),
    _make(
        _SPEC_69A,
        _evaluate_69a,
        queries=("dns_ldap_srv",),
        lookups=("dc_hosts",),
        sentinels=("dns_ldap_srv", "dc_hosts"),
    ),
    _make(
        _SPEC_69B,
        _evaluate_69b,
        queries=("dns_ldap_srv",),
        lookups=("dc_hosts",),
        sentinels=("dns_ldap_srv", "dc_hosts"),
    ),
]
