"""Describe staged UCI changes without trusting the agent's explanation.

Every line in this module is fixed text selected from deterministic rules.
The staged configuration is the only input, so device-controlled values and
agent prose can never become an approval summary.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from . import touched


Fact = touched._Requirement
Facts = set[Fact]
Types = dict[tuple[str, str], str]
Predicate = Callable[[Types, Facts], bool]

CANNOT_DESCRIBE = (
    "Newton cannot describe this change in plain words: read the config lines below."
)
DELETES_LINE = "Removes existing settings from the router."
NOT_DESCRIBED = "Some changes are not described here: read the config lines below."

_ANON_SECTION_RE = re.compile(r"^@([A-Za-z0-9_-]{1,32})\[(?:-?[0-9]{1,3}|\*)\]$")
_FIREWALL_TYPES = {"rule", "redirect", "zone", "forwarding"}
_SPECIFIC_FIREWALL_RULES = {
    "fw-forward-wan",
    "fw-dmz",
    "fw-wan-accept",
    "guest-iso",
    "fw-wan-zone",
}


def _types(facts: Facts) -> Types:
    """Infer each changed section's type from the staged batch.

    Named sections need their section-creating line. Anonymous sections
    carry their type in the section name, so a batch can describe an
    anonymous change without inventing a type from its options.
    """
    types: Types = {}
    for fact in facts:
        if fact.option is None:
            types[(fact.cfg, fact.section)] = fact.value
    for fact in facts:
        key = (fact.cfg, fact.section)
        if key in types:
            continue
        match = _ANON_SECTION_RE.fullmatch(fact.section)
        if match is not None:
            types[key] = match.group(1)
    return types


def _sections(types: Types, config: str, section_type: str) -> set[tuple[str, str]]:
    return {
        key
        for key, value in types.items()
        if key[0] == config and value == section_type
    }


def _values(
    facts: Facts,
    config: str,
    section: str,
    option: str,
) -> list[str]:
    return [
        fact.value
        for fact in facts
        if fact.cfg == config
        and fact.section == section
        and fact.option == option
    ]


def _has_option(
    facts: Facts,
    config: str,
    section: str,
    option: str,
) -> bool:
    return bool(_values(facts, config, section, option))


def _facts_for_sections(
    facts: Facts,
    sections: set[tuple[str, str]],
) -> set[Fact]:
    return {fact for fact in facts if (fact.cfg, fact.section) in sections}


def _fw_forward_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    matches: set[tuple[str, str]] = set()
    for config, section in _sections(types, "firewall", "redirect"):
        if "wan" in _values(facts, config, section, "src"):
            matches.add((config, section))
    return matches


def _fw_dmz_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    matches: set[tuple[str, str]] = set()
    for config, section in _sections(types, "firewall", "redirect"):
        if "wan" not in _values(facts, config, section, "src"):
            continue
        if not _has_option(facts, config, section, "dest_ip"):
            continue
        if _has_option(facts, config, section, "src_dport"):
            continue
        if _has_option(facts, config, section, "dest_port"):
            continue
        matches.add((config, section))
    return matches


def _fw_wan_accept_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    matches: set[tuple[str, str]] = set()
    for config, section in _sections(types, "firewall", "rule"):
        if "wan" not in _values(facts, config, section, "src"):
            continue
        if "ACCEPT" not in _values(facts, config, section, "target"):
            continue
        matches.add((config, section))
    return matches


def _wan_zone_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    """The wan zone made or changed here to accept incoming traffic."""
    return {
        (config, section)
        for config, section in _sections(types, "firewall", "zone")
        if "wan" in _values(facts, config, section, "name")
        and (
            "ACCEPT" in _values(facts, config, section, "input")
            or "ACCEPT" in _values(facts, config, section, "forward")
        )
    }


def _mgmt_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    matches: set[tuple[str, str]] = set()
    for config, section_type in (("uhttpd", "uhttpd"), ("dropbear", "dropbear")):
        for config_name, section in _sections(types, config, section_type):
            for option in ("Interface", "listen_http", "listen_https"):
                if any(
                    "0.0.0.0" in value
                    or "[::]" in value
                    or value.isdigit()
                    for value in _values(facts, config_name, section, option)
                ):
                    matches.add((config_name, section))
                    break
    for config, section in _sections(types, "dropbear", "dropbear"):
        if (config, section) in matches:
            continue
        if _has_option(facts, config, section, "Interface"):
            continue
        if {"on", "clients"} & set(_values(facts, config, section, "GatewayPorts")):
            matches.add((config, section))
    return matches


def _guest_forwarding_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    """Forwardings that give a zone made in this batch internet access.

    A zone counts only when this batch creates it, a forwarding from it
    reaches ``wan`` and no forwarding in the batch lets it reach anything
    else.  Newton cannot see the rest of the router's firewall, so the
    line it prints says "no new access", not "isolated".
    """
    new_zones = {
        value
        for config, section in _sections(types, "firewall", "zone")
        for value in _values(facts, config, section, "name")
    }
    forwardings = _sections(types, "firewall", "forwarding")
    matches: set[tuple[str, str]] = set()
    for config, section in forwardings:
        sources = set(_values(facts, config, section, "src")) & new_zones
        if not sources or "wan" not in _values(facts, config, section, "dest"):
            continue
        reaches_elsewhere = any(
            set(_values(facts, other_config, other, "src")) & sources
            and any(
                dest != "wan"
                for dest in _values(facts, other_config, other, "dest")
            )
            for other_config, other in forwardings
        )
        if not reaches_elsewhere:
            matches.add((config, section))
    return matches


def _guest_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    """The zones made in this batch that a matching forwarding starts from."""
    sources = {
        value
        for config, section in _guest_forwarding_sections(types, facts)
        for value in _values(facts, config, section, "src")
    }
    return {
        key
        for key in _sections(types, "firewall", "zone")
        if set(_values(facts, key[0], key[1], "name")) & sources
    }


def _dhcp_host_sections(types: Types) -> set[tuple[str, str]]:
    return _sections(types, "dhcp", "host")


def _dns_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    matches = _sections(types, "dhcp", "domain")
    for config, section in _sections(types, "dhcp", "dnsmasq"):
        if any(
            _has_option(facts, config, section, option)
            for option in ("server", "address", "local", "domain")
        ):
            matches.add((config, section))
    return matches


def _lan_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    matches = _sections(types, "network", "device")
    for config, section in _sections(types, "network", "interface"):
        if any(
            _has_option(facts, config, section, option)
            for option in ("ipaddr", "netmask", "gateway", "proto")
        ):
            matches.add((config, section))
    return matches


def _wifi_sections(types: Types, facts: Facts) -> set[tuple[str, str]]:
    matches: set[tuple[str, str]] = set()
    for config, section in _sections(types, "wireless", "wifi-iface"):
        if any(
            _has_option(facts, config, section, option)
            for option in (
                "ssid",
                "key",
                "encryption",
                "disabled",
                "ieee80211w",
                "wps_pushbutton",
            )
        ):
            matches.add((config, section))
    for config, section in _sections(types, "wireless", "wifi-device"):
        if any(
            _has_option(facts, config, section, option)
            for option in ("country", "txpower", "channel")
        ):
            matches.add((config, section))
    return matches


def _hostname_facts(facts: Facts) -> set[Fact]:
    return {
        fact
        for fact in facts
        if fact.cfg == "system" and fact.option == "hostname"
    }


def _label_facts(types: Types, facts: Facts) -> set[Fact]:
    # The description and notes of the system section are text LuCI shows;
    # nothing on the router acts on them.  The batch alone must show the
    # section is of type system (``@system[0]`` or a typed line): a named
    # section of unknown type may be an LED or anything else.
    return {
        fact
        for fact in facts
        if fact.cfg == "system"
        and fact.option in {"description", "notes"}
        and types.get((fact.cfg, fact.section)) == "system"
    }


def _fw_other_sections(types: Types) -> set[tuple[str, str]]:
    return {
        key
        for key, value in types.items()
        if key[0] == "firewall" and value in _FIREWALL_TYPES
    }


_RULES: tuple[tuple[str, Predicate, str, str | None], ...] = (
    (
        "fw-forward-wan",
        lambda types, facts: bool(_fw_forward_sections(types, facts)),
        "Opens a port from the internet to a device on your network.",
        "Smaller alternative: reach it through a WireGuard/VPN connection instead of opening a public port.",
    ),
    (
        "fw-dmz",
        lambda types, facts: bool(_fw_dmz_sections(types, facts)),
        "Sends ALL unsolicited internet traffic to one device on your network.",
        "Smaller alternative: forward only the single port that device needs.",
    ),
    (
        "fw-wan-accept",
        lambda types, facts: bool(_fw_wan_accept_sections(types, facts)),
        "Lets the internet connect to the router or to devices on your network.",
        "Smaller alternative: allow it from the VPN only.",
    ),
    (
        "fw-wan-zone",
        lambda types, facts: bool(_wan_zone_sections(types, facts)),
        "Makes the internet side of the router accept incoming connections.",
        None,
    ),
    (
        "mgmt-wan",
        lambda types, facts: bool(_mgmt_sections(types, facts)),
        "Changes who can reach the router's login pages or SSH.",
        "Smaller alternative: keep the admin pages on the LAN and reach them over a VPN.",
    ),
    (
        "guest-iso",
        lambda types, facts: bool(_guest_sections(types, facts)),
        "Gives a new, separate network internet access.",
        None,
    ),
    (
        "dhcp-host",
        lambda types, facts: bool(_dhcp_host_sections(types)),
        "Reserves a fixed address for a device.",
        None,
    ),
    (
        "dns",
        lambda types, facts: bool(_dns_sections(types, facts)),
        "Changes how names are looked up on your network.",
        None,
    ),
    (
        "lan-addr",
        lambda types, facts: bool(_lan_sections(types, facts)),
        "Changes a network address of the router: a mistake can cut you off from it.",
        None,
    ),
    (
        "wifi",
        lambda types, facts: bool(_wifi_sections(types, facts)),
        "Changes Wi-Fi name, password, security or radio settings.",
        None,
    ),
    (
        "hostname",
        lambda types, facts: bool(_hostname_facts(facts)),
        "Renames the router.",
        None,
    ),
    (
        "system-label",
        lambda types, facts: bool(_label_facts(types, facts)),
        "Changes the router's description or notes text, a label only.",
        None,
    ),
    (
        "fw-other",
        lambda types, facts: bool(_fw_other_sections(types)),
        "Changes the firewall rules.",
        None,
    ),
)


def _matched_rule_ids(types: Types, facts: Facts) -> list[str]:
    matched = [
        rule_id
        for rule_id, predicate, _line, _alternative in _RULES
        if predicate(types, facts)
    ]
    if any(rule_id in matched for rule_id in _SPECIFIC_FIREWALL_RULES):
        matched = [rule_id for rule_id in matched if rule_id != "fw-other"]
    return matched


def _covered_facts(
    types: Types,
    facts: Facts,
    matched: list[str],
) -> set[Fact]:
    covered: set[Fact] = set()
    for rule_id in matched:
        if rule_id == "fw-forward-wan":
            covered.update(_facts_for_sections(facts, _fw_forward_sections(types, facts)))
        elif rule_id == "fw-dmz":
            covered.update(_facts_for_sections(facts, _fw_dmz_sections(types, facts)))
        elif rule_id == "fw-wan-zone":
            covered.update(_facts_for_sections(facts, _wan_zone_sections(types, facts)))
        elif rule_id == "fw-wan-accept":
            covered.update(_facts_for_sections(facts, _fw_wan_accept_sections(types, facts)))
        elif rule_id == "mgmt-wan":
            covered.update(_facts_for_sections(facts, _mgmt_sections(types, facts)))
        elif rule_id == "guest-iso":
            covered.update(_facts_for_sections(facts, _guest_sections(types, facts)))
            covered.update(
                _facts_for_sections(facts, _guest_forwarding_sections(types, facts))
            )
        elif rule_id == "dhcp-host":
            covered.update(_facts_for_sections(facts, _dhcp_host_sections(types)))
        elif rule_id == "dns":
            covered.update(_facts_for_sections(facts, _dns_sections(types, facts)))
        elif rule_id == "lan-addr":
            covered.update(_facts_for_sections(facts, _lan_sections(types, facts)))
        elif rule_id == "wifi":
            covered.update(_facts_for_sections(facts, _wifi_sections(types, facts)))
        elif rule_id == "hostname":
            hostname_facts = _hostname_facts(facts)
            covered.update(hostname_facts)
            hostname_sections = {
                (fact.cfg, fact.section) for fact in hostname_facts
            }
            covered.update(
                fact
                for fact in facts
                if (fact.cfg, fact.section) in hostname_sections
                and fact.option is None
            )
        elif rule_id == "system-label":
            covered.update(_label_facts(types, facts))
        elif rule_id == "fw-other":
            covered.update(_facts_for_sections(facts, _fw_other_sections(types)))
    return covered


def describe(uci_batch: str) -> list[str]:
    """Return up to three plain-language lines for the staged batch.

    The fallback is deliberate: when no deterministic rule fits, Newton
    says that it cannot describe the change instead of inventing a claim
    that the owner might approve as if it were Newton's own.
    """
    facts = set(touched._parse_batch_facts(uci_batch))
    deletes = any(
        line.split(None, 1)[:1] == ["delete"] for line in uci_batch.splitlines()
    )
    if not facts and not deletes:
        return [CANNOT_DESCRIBE]
    # rename and reorder carry no facts, so a rule can cover every fact
    # while a rename turns a label into a working option: such a batch is
    # never "a label only" and never fully described.
    structural = any(
        line.split(None, 1)[:1] in (["rename"], ["reorder"])
        for line in uci_batch.splitlines()
    )
    types = _types(facts)
    matched = _matched_rule_ids(types, facts)
    if structural:
        matched = [rule_id for rule_id in matched if rule_id != "system-label"]
    if not matched and not deletes:
        return [CANNOT_DESCRIBE]
    lines: list[str] = [DELETES_LINE] if deletes else []
    for rule_id, _predicate, line, _alternative in _RULES:
        if rule_id not in matched:
            continue
        if line not in lines:
            lines.append(line)
    if (
        structural
        or facts - _covered_facts(types, facts, matched)
        or (deletes and not matched)
    ):
        if len(lines) >= 3:
            lines = lines[:2]
        lines.append(NOT_DESCRIBED)
    return lines[:3]


def alternatives(uci_batch: str) -> list[str]:
    """Return up to two fixed smaller-change offers for matching rules."""
    facts = set(touched._parse_batch_facts(uci_batch))
    if not facts:
        return []
    types = _types(facts)
    matched = _matched_rule_ids(types, facts)
    offers: list[str] = []
    for rule_id, _predicate, _line, alternative in _RULES:
        if rule_id not in matched or alternative is None:
            continue
        if alternative not in offers:
            offers.append(alternative)
        if len(offers) == 2:
            break
    return offers
