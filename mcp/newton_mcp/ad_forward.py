"""Plan the change that forwards an AD DNS domain to its domain controllers.

The change is dnsmasq conditional forwarding, written the way OpenWrt's
``dhcp`` config documents it (references/openwrt/source/dhcp.txt):

* ``list server '/<domain>/<dc>'`` sends every query for the domain, and
  for names under it, to that upstream server only (dnsmasq's
  ``--server=/domain/ip``).  One line per domain controller.
* ``list rebind_domain '/<domain>/'`` exempts the domain from
  ``--stop-dns-rebind``.  OpenWrt turns that protection on by default
  (``rebind_protection`` is ``1``) and it discards upstream answers in the
  private ranges, which is every answer an AD zone gives.  The option "only
  takes effect if rebind protection is enabled", so the line is planned only
  when the protection is not explicitly off.

This module only builds the lines and judges the router's own text.  It
writes nothing and contacts nothing: the lines go through the same plan,
approval and device-side rollback as every other change.  Nothing here
removes a value: Newton adds what is missing and leaves every other server
entry alone.

What the router's own entries mean was measured with dnsmasq 2.91 on
Linux, not on a router:

* A domain the router marks local-only (dnsmasq's ``local=/<domain>/``
  or its ``server=/<domain>/`` with no address) is planned normally: the
  server entry with an address wins over a local-only entry for the
  same domain, in either order.  When the plan adds the forward, a note
  says so.
* An ``address`` entry for the domain that carries an address
  (``address=/<domain>/1.2.3.4``, ``address=/<domain>/#`` or the
  ``/.<domain>/`` spelling) is refused and nothing is staged: dnsmasq
  answers A and AAAA lookups itself (SRV lookups are still forwarded).
  The owner removes that entry through ``newton_plan_change`` first.
* An ``address`` entry with no address is a local-only entry.  An entry
  for a parent domain or ``/#/`` does not stop the forward.
* ``.<domain>`` and ``<domain>.`` are the domain.  ``*.<domain>`` is
  refused in any of these entries: it beats the forward for every name
  under the domain, the domain controllers included.
* An ``address`` entry with an address, a local-only entry, or a
  ``server`` entry to another address, for a name below the domain does
  not stop the forward of the domain, but it keeps those names from
  reaching the domain controllers: the plan says so in a note.

The router's own text is never mixed into the notes the model reads as
Newton's word.  A note is fixed Newton wording plus the values the caller
gave; the router's entries come back in their own field
(``ForwardPlan.existing_servers``), which the caller wraps as device data.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

#: The most domain controller addresses one plan takes.
MAX_DCS = 8

#: The most characters of a DNS name (RFC 1035, without the root dot).
MAX_DOMAIN = 253

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

_OFF = frozenset({"0", "off", "no", "false", "disabled"})

_TARGET = "@dnsmasq[0]"


class ForwardError(ValueError):
    """A refusal.  The message never carries the rejected value."""


def validate_domain(value: Any) -> str:
    """The domain, lower-cased, or a refusal.

    Letters, digits and hyphens only (LDH), at least two labels (a one-label
    ``/corp/`` would catch every name that ends in it), at most 253
    characters, labels of at most 63, no hyphen at a label's edge, and a last
    label that is not all digits (it would read as an address).  A trailing
    dot, a slash, a hash, a space or a newline is refused: each is syntax of
    the dnsmasq value this becomes.
    """
    if not isinstance(value, str) or not value:
        raise ForwardError("the domain must be a non-empty name")
    if len(value) > MAX_DOMAIN:
        raise ForwardError(f"the domain is longer than {MAX_DOMAIN} characters")
    if not value.isascii():
        raise ForwardError("the domain must use only ASCII letters, digits, hyphens and dots")
    name = value.lower()
    labels = name.split(".")
    if len(labels) < 2:
        raise ForwardError("the domain needs at least two labels, such as corp.example.com")
    for label in labels:
        if _LABEL.fullmatch(label) is None:
            raise ForwardError(
                "the domain must be letters, digits and hyphens in labels of 1 to 63 "
                "characters separated by single dots, with no hyphen at a label's edge"
            )
    if labels[-1].isdigit():
        raise ForwardError("the last label of the domain must not be all digits")
    return name


def validate_dcs(value: Any) -> list[str]:
    """The domain controller addresses, normalised and de-duplicated, or a refusal.

    IPv4 or IPv6 literals only: no port (``#53``), no prefix length, no
    scope (``%eth0``), no name, no extra text.  An unspecified, loopback,
    multicast, link-local or reserved address is refused, and so is a global
    (public) one: an AD zone is forwarded to a server on the owner's own
    network, never to the internet.  The cap counts after de-duplication.
    """
    if not isinstance(value, list) or not value:
        raise ForwardError("dc_addresses must be a non-empty list of IP addresses")
    found: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or item != item.strip():
            raise ForwardError("each domain controller address must be a plain IP address")
        # ipaddress accepts a scope on IPv6 in newer Pythons; a scope or any
        # other punctuation is refused before it is parsed.
        if re.fullmatch(r"[0-9A-Fa-f:.]+", item) is None:
            raise ForwardError("each domain controller address must be a plain IP address")
        try:
            ip = ipaddress.ip_address(item)
        except ValueError:
            raise ForwardError("each domain controller address must be a plain IP address") from None
        if (
            ip.is_unspecified
            or ip.is_loopback
            or ip.is_multicast
            or ip.is_link_local
            or ip.is_reserved
            or ip == ipaddress.ip_address("255.255.255.255")
        ):
            raise ForwardError(
                "a domain controller address must not be unspecified, loopback, "
                "multicast, link-local or reserved"
            )
        if ip.is_global:
            raise ForwardError(
                "a domain controller address must be on a private network, "
                "not a public internet address"
            )
        text = str(ip)
        if text not in found:
            found.append(text)
    if len(found) > MAX_DCS:
        raise ForwardError(f"at most {MAX_DCS} domain controller addresses")
    return found


@dataclass(frozen=True)
class ForwardPlan:
    """What the plan would do on the router that was read."""

    domain: str
    dc_addresses: list[str]
    lines: list[str]
    already_present: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: The router's own entries for this domain that Newton does not add
    #: and leaves alone.  Router text: the caller keeps it as device data.
    existing_servers: list[str] = field(default_factory=list)

    @property
    def noop(self) -> bool:
        return not self.lines

    @property
    def message(self) -> str:
        if not self.noop:
            return ""
        return (
            f"already in place: dnsmasq forwards {self.domain} to "
            f"{', '.join(self.dc_addresses)}; nothing to change"
        )


def _same_address(left: str, right: str) -> bool:
    """True when two address texts name the same address.

    ``fd00:0:0:0:0:0:0:1`` and ``fd00::1`` are one address, so the
    router's own spelling of it must not make Newton add the entry a
    second time.  An IPv4-mapped IPv6 address (``::ffff:192.0.2.10``)
    names the IPv4 address it maps.  A scoped address
    (``fd00::1%br-lan``) is compared as text: a scope names an
    interface, and a forward through one was not seen to work, so the
    scoped text is never proof that the address without the scope is there.  A text that is not an address
    is compared as text, exactly as before, and never raises.
    """
    if left.lower() == right.lower():
        return True
    first = _address(left)
    second = _address(right)
    if first is None or second is None:
        return False
    first4 = _as_ipv4(first)
    second4 = _as_ipv4(second)
    if isinstance(first4, ipaddress.IPv4Address) and isinstance(second4, ipaddress.IPv4Address):
        return first4 == second4
    return first == second


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address a text names, or None.

    A text with a scope (``fd00::1%br-lan``) is not an address here:
    it is compared as text, exactly as it comes.  A text that is not an
    address gives None, never an error.
    """
    if "%" in text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _as_ipv4(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """The IPv4 address an address names, mapped or not."""
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped if mapped is not None else address


def _values(raw: str) -> list[str]:
    """The values of one ``uci show`` line: ``'a' 'b'`` or ``a``."""
    try:
        return shlex.split(raw)
    except ValueError:
        return []


def _dnsmasq(text: str) -> dict[str, list[str]]:
    """The options of the dnsmasq section in ``uci show dhcp`` text.

    The text is the router's own: it is only parsed, never obeyed.  A router
    with no dnsmasq section or more than one is refused, since the lines
    address the first dnsmasq section.
    """
    names: list[str] = []
    for line in text.splitlines():
        head, sep, kind = line.partition("=")
        if sep and kind.strip() == "dnsmasq" and head.startswith("dhcp.") and head.count(".") == 1:
            names.append(head[len("dhcp."):])
    if not names:
        raise ForwardError("the router has no dnsmasq section in its dhcp config")
    if len(names) > 1:
        raise ForwardError(
            "the router has more than one dnsmasq section; Newton plans this "
            "change for a router with one"
        )
    prefix = f"dhcp.{names[0]}."
    options: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        key, sep, raw = line[len(prefix):].partition("=")
        if sep and re.fullmatch(r"[A-Za-z0-9_]+", key):
            options.setdefault(key, []).extend(_values(raw))
    return options


def _dnsmasq_domains(value: str) -> list[str]:
    """The domains a dnsmasq value names.

    dnsmasq writes a domain as ``/<domain>/`` and one value may name
    several domains (``/a/b/``).  To dnsmasq ``.a``, ``a.`` and ``a`` are
    one name here, so both dots are dropped; ``*.a`` (only the names under
    it) is another name and is kept.  The router's own text is only read,
    never obeyed.
    """
    parts = (part.lower().rstrip(".").removeprefix(".") for part in value.split("/"))
    return [part for part in parts if part]


def _split_entry(entry: str) -> tuple[list[str], str]:
    """The domains and the address of one ``server`` or ``address`` entry.

    The value is ``/<domain>[/<domain>...]/<address>``: the domains come
    first and the address after the last slash.  An entry that names no
    address (``/<domain>/``) gives an empty address, and a value that is
    not a domain entry at all gives no domains.
    """
    if not entry.startswith("/"):
        return [], ""
    domain_part, _, address = entry[1:].rpartition("/")
    return _dnsmasq_domains(domain_part), address


def _local_only_names(options: dict[str, list[str]]) -> set[str]:
    """The names the router marks local-only.

    dnsmasq's ``local=/<name>/`` and its ``server=/<name>/`` with no
    address after the name both mark the name local-only: the router
    answers it itself.  The names are taken as they come, lower-cased.
    """
    names: set[str] = set()
    for entry in options.get("local", []):
        names.update(_dnsmasq_domains(entry))
    # an address entry with no address is the same as a local entry
    for domains, address in _address_entries(options):
        if not address:
            names.update(domains)
    for entry in options.get("server", []):
        domains, address = _split_entry(entry)
        if not address:
            names.update(domains)
    return names


def _address_entries(options: dict[str, list[str]]) -> list[tuple[list[str], str]]:
    """The names and the addresses of the router's own address entries.

    dnsmasq's ``address=/<name>/[#[<ip>]]`` gives a name an answer of
    its own: with an address, dnsmasq answers the name locally instead
    of forwarding it.
    """
    entries: list[tuple[list[str], str]] = []
    for entry in options.get("address", []):
        domains, address = _split_entry(entry)
        if domains:
            entries.append((domains, address))
    return entries


def _below(name: str, domain: str) -> bool:
    """True when the name is under the domain, label by label.

    ``dc1.corp.example.com`` is under ``corp.example.com``;
    ``notcorp.example.com`` is not.
    """
    return name.endswith("." + domain)


def build_plan(domain: Any, dcs: Any, dhcp_text: str) -> ForwardPlan:
    """The lines to add, given the router's ``uci show dhcp`` text."""
    name = validate_domain(domain)
    addresses = validate_dcs(dcs)
    options = _dnsmasq(dhcp_text)
    notes: list[str] = []

    # An address entry for the domain (or for every name under it,
    # "/.<domain>/") gives dnsmasq its own A and AAAA answers: the names
    # of the domain controllers would not resolve to them.  Nothing is staged.
    for domains, address in _address_entries(options):
        if address and (name in domains or f"*.{name}" in domains):
            raise ForwardError(
                f"the router answers {name} itself: an address entry for the domain "
                "holds an address, so dnsmasq answers its A and AAAA lookups locally "
                "and they do not reach the domain controllers; the owner removes that entry "
                "through newton_plan_change first, then plans again"
            )

    if f"*.{name}" in _local_only_names(options):
        raise ForwardError(
            f"the router marks every name under {name} local-only (a wildcard local, "
            "server or address entry with no address), so their lookups do not reach "
            "the domain controllers; the owner removes that entry through "
            "newton_plan_change first, then plans again"
        )

    servers = options.get("server", [])
    prefix = f"/{name}/"

    def for_domain(entry: str) -> str | None:
        """The address part of the router's entry for this domain, or None.

        The domain is matched as dnsmasq reads it (case, the two dots, several
        domains in one entry); an entry for another domain is not ours.
        rebind_domain is not read this way: there "/.<domain>/" is no exception,
        so only the exact "/<domain>/" counts; for another spelling that does work
        ("/<domain>./", the bare name, a parent) the plan adds a harmless second line.
        """
        domains, address = _split_entry(entry)
        return address if name in domains else None

    def is_planned(entry: str, address: str) -> bool:
        """True when the router's entry is the one Newton would add.

        The address is matched by the address it names, so the router's own
        spelling of it does not make a second entry.
        """
        rest = for_domain(entry)
        return rest is not None and _same_address(rest, address)

    lines: list[str] = []
    present: list[str] = []
    added_servers = 0
    for address in addresses:
        entry = f"/{name}/{address}"
        if any(is_planned(e, address) for e in servers):
            present.append(entry)
        else:
            lines.append(f"add_list dhcp.{_TARGET}.server='{entry}'")
            added_servers += 1

    others = sorted(
        e for e in servers
        if for_domain(e) is not None and not any(is_planned(e, a) for a in addresses)
    )
    if any(_split_entry(e)[1] for e in others):
        # The note is Newton's own wording; the router's own entries are
        # not in it, they are in their own field as device data.
        notes.append(
            f"the router already forwards {name} to other servers; Newton leaves "
            "them as they are and only adds the addresses above; the router's own "
            "entries are in the existing_servers field"
        )

    local_only = _local_only_names(options)
    if name in local_only and added_servers:
        notes.append(
            f"the router marks {name} as local-only (a local entry, or a server "
            "or address entry with no address); the forward added here "
            "overrides it, so lookups for the domain reach the domain controllers"
        )

    below = {n for n in local_only if _below(n, name)}
    below.update(
        n for domains, address in _address_entries(options) if address
        for n in domains if _below(n, name)
    )
    for entry in servers:
        domains, address = _split_entry(entry)
        if address and not any(_same_address(address, a) for a in addresses):
            below.update(n for n in domains if _below(n, name))
    if below:
        notes.append(
            "the router has more specific entries for some names below the domain, "
            "so those names do not reach the domain controllers"
        )

    protection = options.get("rebind_protection", ["1"])
    protected = not (protection and protection[-1].lower() in _OFF)
    if protected:
        if prefix.lower() not in {e.lower() for e in options.get("rebind_domain", [])}:
            lines.append(f"add_list dhcp.{_TARGET}.rebind_domain='{prefix}'")
        else:
            present.append(f"rebind_domain {prefix}")
    else:
        notes.append(
            "rebind protection is off on this router, so no rebind_domain line is needed; "
            "if it is turned on later, add the domain to rebind_domain"
        )

    dnssec = options.get("dnssec", [])
    if dnssec and dnssec[-1].lower() not in _OFF:
        notes.append(
            "dnssec is on; Newton does not change it, but check it first if lookups of "
            f"{name} fail after this change (an AD zone is not signed)"
        )
    return ForwardPlan(name, addresses, lines, present, notes, others)
