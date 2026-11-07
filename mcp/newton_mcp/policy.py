"""Newton approval policy: device profiles (K5) and the leash (K6, design 5.2).

``classify(device, uci_batch, diff, section_facts=None)`` decides for one
staged plan whether the apply needs an out-of-band approval and why.  It
learns the same rules as the router-side leash (design 5.2, run by ``seal``),
so a host that has no router facts yet and a host that has them agree
wherever the diff alone carries the facts:

* ``profile = "prod"`` (the fail-safe default when the inventory sets none):
  every write requires approval (code ``profile-prod``).
* ``profile = "lab"``: no approval, EXCEPT leash operations, which require
  approval on every profile.

The leash (risk CRITICAL) is judged on the staged diff (the ``uci changes``
output between the ``----- diff`` markers).  A leading ``-``/``@``/``^``
marks a delete/rename/reorder line (a list add may show either a leading
``+`` or the ``option+='value'`` form, a list-item delete the matching
``option-='value'`` form); a new section shows as ``config.name=type``, its
options as ``config.name.option='value'``; an existing anonymous section
shows as ``config.@type[N].option='value'``; values may be quoted or not.
The wan-zone list comes from the device inventory (``device.wan_zones``,
default ``("wan",)``).  Every reason string starts with the 5.2 code it
implements (``mgmt-zone: ...``, ``wan-rule: ...``).

``section_facts`` is the optional bridge to what the router knows: a mapping
from ``(config, section)`` to a ``(type, name)`` pair (either part may be
``None``), taken from the router's ``section <cfg> <section> <type|->
<name|->`` seal lines (``-`` means none; see ``parse_section_fact_line``).
A group with a router section fact counts as IDENTIFIED by that type and
name, so the fail-safe ``section-unidentified`` reasons fire only when
neither the diff nor the facts name the section (and a zone has no
non-empty name in either view).  With ``section_facts=None`` the behaviour
for an anonymous existing section stays fail-safe as before.

Committed-view limits (design 5.2 lets the router read the committed view;
the host has only the diff, the batch and the facts).  Where a rule needs a
committed value the diff cannot supply, the host fails safe -- the reason
fires -- EXCEPT where firing on every unknown would flag changes the router
itself allows; each such rule says so in a comment next to it:

* a rule's committed ``src``, a forwarding's committed ``src``/``dest`` and
  a redirect's committed ``src`` are unknown for an existing section whose
  identifying options are not in the diff -> the reason fires (fail safe);
* a deleted option's value and every option of a deleted section are
  unknown -> ``path-option`` fires (fail safe);
* an existing zone's committed ``network`` (mgmt-zone identity by network,
  zone-exposure network gain) and a route's committed ``interface`` are
  unknown -> only the staged (diff) values count; the design's intended
  differences keep those cases on the router's side of the differential
  table, because fail-safe firing would flag every zone change.

The plan's verification probes are fixed code checked by
``newton_mcp.probes`` (the old ``check`` parameter and
``check_is_trivial`` are gone).

``uci_batch`` keeps the staging-verb refusal of ``scripts/owrt-safe-apply.sh
stage``: only set/add/add_list/del_list/delete/rename/reorder are allowed;
commit/import/revert (and anything else) raise ``ValueError``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping


PROFILES = ("lab", "prod")
DEFAULT_PROFILE = "prod"
DEFAULT_MGMT_INTERFACE = "lan"
DEFAULT_MGMT_ZONE = "lan"
DEFAULT_WAN_ZONES = ("wan",)        # used when the device has no wan_zones attribute
WILDCARD_SOURCE = "*"               # uci's src '*' matches every zone, wan included
ACCEPT_TARGET = "ACCEPT"
DROP_TARGETS = ("DROP", "REJECT")   # the only wan-zone tightenings (case-insensitive)
MANAGEMENT_CONFIGS = ("dropbear", "rpcd", "uhttpd")
KNOWN_PACKAGES = (
    "dhcp", "dropbear", "firewall", "luci", "network", "rpcd",
    "system", "uhttpd", "upnpd", "wireless", "https-dns-proxy",
    "newton_wanhealth",
)
WAN_ZONE_EXEMPT_OPTIONS = ("output", "log", "log_limit", "mtu_fix", "masq", "masq6")
ZONE_EXPOSURE_CAPTURE_OPTIONS = ("device", "subnet", "family", "extra", "extra_src", "extra_dest")
ZONE_EXPOSURE_POLICY_OPTIONS = ("input", "forward")
WAN_NETWORK_NAMES = ("wan", "wan6")
BRIDGE_SECTION_TYPES = ("device", "bridge-vlan")
ROUTE_SECTION_TYPES = ("route", "route6")
EXEC_OPTION_NAMES = {
    "dhcp": ("dhcpscript", "leasetrigger"),
    "system": ("log_file",),
    "network": ("pppd_options",),
}
UPNP_OPTIONS = ("enabled", "enable_upnp", "enable_natpmp")
# the fail-safe set: options on an existing zone the diff cannot
# identify that may change the management or wan zone
MGMT_ZONE_FAILSAFE_OPTIONS = (
    "input", "forward", "network", "name",
    "device", "subnet", "extra", "extra_src", "extra_dest", "masq_src", "masq_dest",
)
STAGING_VERBS = ("set", "add", "add_list", "del_list", "delete", "rename", "reorder")
PROD_REASON = "profile 'prod': every write requires approval"
RISK_CRITICAL = "critical"
RISK_LOW = "low"

ANON_SECTION_RE = re.compile(r"^@([A-Za-z0-9_-]{1,32})\[([0-9]{1,3})\]$")
CONFIG_NAME_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
SECTION_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SECTION_TYPE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
OPTION_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
OP_CHARS = "-+@^"

# mask placeholder forms the diff maskers produce: ``<masked>`` literal
# (scripts/owrt-change.sh mask_secrets), ``<masked: ...>`` (the too-many
# assignments guard), and ``<redacted:hex>`` (mcp.newton_mcp.redact).  A
# section-type value matching one of these is a name the masker could not
# show us, so it cannot be a real UCI type and the policy treats it as an
# unknown section type rather than taking it at face value.
_MASKED_TYPE_RE = re.compile(r"^<(?:masked(?:[^>]*)?|redacted:[^>]*)>$")

# path-option exemptions (design 5.2): an address prefix, a web URL (not
# file://) or a rate; everything else that holds a '/' names a file
PATH_PREFIX_EXEMPT_RE = re.compile(r"[0-9A-Fa-f.:]+/[0-9]{1,3}")
PATH_RATE_EXEMPT_RE = re.compile(r"[0-9]+/(second|minute|hour|day)")
PATH_URL_EXEMPT_RE = re.compile(r"https?://")


@dataclass(frozen=True)
class Change:
    """One parsed ``uci changes`` line; ``config is None`` means unparsed."""

    op: str                    # "" set / new section, "-" delete or del_list, "+" add_list, "@" rename, "^" reorder
    config: str | None
    section: str
    option: str | None
    value: str | None          # unquoted staged value, when the line has one
    line: str

    @property
    def parsed(self) -> bool:
        return self.config is not None


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_diff_line(line: str) -> Change | None:
    """Parse one ``uci changes`` line; None for blank lines, unparsed Change for garbage."""
    text = line.strip()
    if not text:
        return None
    op = ""
    if text[0] in OP_CHARS:
        op, text = text[0], text[1:]
    config, dot, rest = text.partition(".")
    if not dot or not CONFIG_NAME_RE.fullmatch(config):
        return Change(op, None, text, None, None, text)
    path, eq, raw_value = rest.partition("=")
    if path.endswith(("+", "-")):
        # `option+='value'` / `option-='value'` put the list marker on the option
        op, path = path[-1], path[:-1]
    value = _unquote(raw_value) if eq else None
    if "." in path:
        section, _, option = path.rpartition(".")
    else:
        section, option = path, None
    if not (SECTION_NAME_RE.fullmatch(section) or ANON_SECTION_RE.fullmatch(section)):
        return Change(op, None, text, None, None, text)
    if option is not None and not OPTION_NAME_RE.fullmatch(option):
        return Change(op, None, text, None, None, text)
    return Change(op, config, section, option, value, text)


def parse_section_fact_line(line: str) -> tuple[tuple[str, str], tuple[str | None, str | None]] | None:
    """Parse one router ``section <cfg> <section> <type|-> <name|->`` line.

    Returns ``((config, section), (type, name))`` with ``-`` mapped to
    ``None``, or None when the line is not a section fact line.
    """
    parts = line.split()
    if len(parts) != 4:
        return None
    cfg, sec, typ, nam = parts
    if not CONFIG_NAME_RE.fullmatch(cfg):
        return None
    if not (SECTION_NAME_RE.fullmatch(sec) or ANON_SECTION_RE.fullmatch(sec)):
        return None
    fact_type = None if typ == "-" else typ
    fact_name = None if nam == "-" else nam
    if fact_type is not None and not SECTION_TYPE_RE.fullmatch(fact_type):
        fact_type = None
    if fact_name is not None and not IDENTIFIER_RE.fullmatch(fact_name):
        fact_name = None
    return (cfg, sec), (fact_type, fact_name)


@dataclass
class SectionGroup:
    """All diff lines touching one (config, section) pair, plus what the diff and the facts show."""

    config: str
    section: str               # the group key: the OLD name for a renamed section
    changes: list[Change] = field(default_factory=list)
    anon_type: str | None = None     # firewall.@zone[1] -> "zone": type shown, identity not
    section_type: str | None = None  # from a `config.name=type` line: a new section
    is_new: bool = False
    renamed: bool = False
    reordered: bool = False
    deleted: bool = False
    new_name: str | None = None      # the target of a section rename
    fact: tuple[str | None, str | None] | None = None   # the router's (type, name) for this section

    def resolved_type(self) -> str | None:
        """The section type: the new-section line, else the router fact, else the @type token."""
        if self.section_type is not None:
            return self.section_type
        if self.fact is not None:
            return self.fact[0]
        return self.anon_type

    def option_state(self, name: str) -> tuple[str, str | None]:
        """('set', value) | ('deleted', None) | ('absent', None) | ('unknown', None).

        'absent' is definitive only for new sections (they show every option)
        or when the diff deletes the option; otherwise the router's state
        could hold anything, which is 'unknown'.
        """
        state, value = ("absent", None) if self.is_new else ("unknown", None)
        for change in self.changes:
            if change.option != name:
                continue
            if change.op == "-":
                state, value = "deleted", None
            else:
                state, value = "set", change.value
        return state, value

    def network_tokens(self) -> list[str]:
        """The staged ``network`` members the diff shows (split on blanks, like the router)."""
        tokens: list[str] = []
        for change in self.changes:
            if change.option != "network" or change.op == "-" or change.value is None:
                continue
            tokens.extend(member for member in change.value.split() if member)
        return tokens


def _groups(changes: list[Change], section_facts: Mapping[tuple[str, str], tuple[str | None, str | None]] | None) -> dict[tuple[str, str], SectionGroup]:
    # a section rename groups under the old name; later lines that name the
    # new name join that group (design 5.2)
    oldof: dict[tuple[str, str], str] = {}
    for change in changes:
        if change.op == "@" and change.option is None and change.value is not None and SECTION_NAME_RE.fullmatch(change.value):
            key = (change.config, change.value)
            if key not in oldof:
                oldof[key] = change.section
    groups: dict[tuple[str, str], SectionGroup] = {}

    def group_for(config: str, section: str) -> SectionGroup:
        key = (config, section)
        group = groups.get(key)
        if group is None:
            anon = ANON_SECTION_RE.fullmatch(section)
            group = SectionGroup(config, section, anon_type=anon.group(1) if anon else None)
            groups[key] = group
        return group

    for change in changes:
        section = change.section
        mapped = oldof.get((change.config, section))
        group = group_for(change.config, mapped if mapped is not None else section)
        group.changes.append(change)
        if change.option is None:
            if change.op == "-":
                group.deleted = True
            elif change.op == "@":
                group.renamed = True
                group.new_name = change.value
            elif change.op == "^":
                group.reordered = True
            elif change.op == "" and change.value is not None and not ANON_SECTION_RE.fullmatch(section):
                if _MASKED_TYPE_RE.fullmatch(change.value):
                    # the masker turned the section type into a placeholder
                    # (e.g. ``<masked>``).  It is not a real UCI type; treat
                    # it as unknown so the dispatch falls into the
                    # ``section_type is None`` path instead of pretending it
                    # is a name we never heard of (the raw diff
                    # ``network.br_auth='device'`` fires bridge-member, the
                    # masked diff would otherwise be free on the host).
                    group.section_type = None
                else:
                    group.section_type = change.value
                group.is_new = True
        elif change.op == "@" and change.value is not None and OPTION_NAME_RE.fullmatch(change.value):
            # an option rename counts as a change to both options; the new
            # option's staged value (the renamed option's value) is not in
            # the diff, so it carries value None (unknown)
            group.changes.append(Change("", change.config, section, change.value, None, change.line))
    if section_facts is not None:
        for group in groups.values():
            fact = section_facts.get((group.config, group.section))
            if fact is None and group.renamed and group.new_name is not None:
                # the seal prints a renamed anonymous section under its new name
                fact = section_facts.get((group.config, group.new_name))
            if fact is not None:
                group.fact = fact
    return groups


def _device_settings(device: Any) -> tuple[str, str, str, tuple[str, ...]]:
    profile = getattr(device, "profile", DEFAULT_PROFILE)
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ValueError(f"invalid profile {profile!r}: profile must be 'lab' or 'prod' (inventory error)")
    mgmt_interface = getattr(device, "mgmt_interface", DEFAULT_MGMT_INTERFACE)
    mgmt_zone = getattr(device, "mgmt_zone", DEFAULT_MGMT_ZONE)
    for label, value in (("mgmt_interface", mgmt_interface), ("mgmt_zone", mgmt_zone)):
        if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
            raise ValueError(f"invalid {label} {value!r}: must be a non-empty name of [A-Za-z0-9_-] (inventory error)")
    wan_zones_raw = getattr(device, "wan_zones", DEFAULT_WAN_ZONES)
    if isinstance(wan_zones_raw, str) or not isinstance(wan_zones_raw, (list, tuple)):
        raise ValueError(f"invalid wan_zones {wan_zones_raw!r}: must be a list of zone names (inventory error)")
    wan_zones = tuple(wan_zones_raw)
    if not wan_zones or any(not isinstance(zone, str) or not IDENTIFIER_RE.fullmatch(zone) for zone in wan_zones):
        raise ValueError("invalid wan_zones: must be a non-empty list of [A-Za-z0-9_-] zone names (inventory error)")
    return profile, mgmt_interface, mgmt_zone, wan_zones


def _require_staging_verbs(uci_batch: str) -> None:
    if not isinstance(uci_batch, str):
        raise ValueError("uci_batch must be a string")
    for raw in uci_batch.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        verb = line.split(None, 1)[0]
        if verb not in STAGING_VERBS:
            raise ValueError(f"only {'/'.join(STAGING_VERBS)} are allowed, got: {line[:80]}")


def _is_accept(value: str | None) -> bool:
    return value is not None and value.upper() == ACCEPT_TARGET


def _path_is_bad(token: str) -> bool:
    if "/" not in token:
        return False
    if PATH_URL_EXEMPT_RE.match(token):
        return False   # only http(s):// is exempt; file:// falls through
    if PATH_PREFIX_EXEMPT_RE.fullmatch(token):
        return False
    if PATH_RATE_EXEMPT_RE.fullmatch(token):
        return False
    return True


# ---- one group's reasons -------------------------------------------------

def _zone_names(group: SectionGroup) -> list[str]:
    """The zone's ``name`` option values: the router fact's (staged else
    committed) plus every name the diff sets, empties dropped."""
    names: list[str] = []
    if group.fact is not None and group.fact[1]:
        names.append(group.fact[1])
    for change in group.changes:
        if change.option == "name" and change.op != "-" and change.value:
            names.extend(token for token in change.value.split() if token)
    return names


def _zone_reasons(group: SectionGroup, mgmt_interface: str, mgmt_zone: str, wan_zones: tuple[str, ...]) -> list[str]:
    names = _zone_names(group)
    snippet = group.changes[0].line[:120]
    identified = group.is_new or group.fact is not None

    if not identified:
        # fail-safe as before the router facts existed: an existing zone the
        # diff cannot identify may be the management zone or a wan zone
        for change in group.changes:
            piece = change.line[:120]
            if change.option is None:
                return [f"mgmt-zone: zone change on an unidentified zone that may be the management zone '{mgmt_zone}' or a wan zone: {piece}"]
            if change.option in ZONE_EXPOSURE_POLICY_OPTIONS and change.op != "-" and _is_accept(change.value):
                return [f"wan-zone: WAN exposure: {change.option}='{ACCEPT_TARGET}' on an unidentified zone that may be a wan zone or the management zone '{mgmt_zone}': {piece}"]
            if change.option in MGMT_ZONE_FAILSAFE_OPTIONS:
                return [f"mgmt-zone: '{change.option}' change on an unidentified zone that may be the management zone '{mgmt_zone}' or a wan zone: {piece}"]
        return []

    network = group.network_tokens()
    # The router also identifies the mgmt zone by the COMMITTED network
    # holding the mgmt interface, and the wan zone by the committed name;
    # neither is on the host.  A name change on an existing zone hides the
    # old name, so the zone may still be the mgmt zone or a wan zone: fail
    # safe.  An unchanged committed network cannot be seen at all; the
    # design keeps that difference on the router's side (intended
    # differences, 5.2).
    name_changed = not group.is_new and any(c.option == "name" and c.op != "-" for c in group.changes)
    is_mgmt = mgmt_zone in names or mgmt_interface in network or name_changed
    is_wan = any(name in wan_zones for name in names) or name_changed
    label = names[0] if names else group.section

    reasons: list[str] = []
    if is_mgmt:
        if mgmt_zone in names:
            reasons.append(f"mgmt-zone: change to the management zone '{mgmt_zone}' (firewall.{group.section}): {snippet}")
        elif mgmt_interface in network:
            reasons.append(
                f"mgmt-zone: new zone '{label}' lists the management interface '{mgmt_interface}' in its network: {snippet}"
            )
        else:
            reasons.append(
                f"mgmt-zone: the zone's name changes and the diff cannot show the old name (it may be the management zone '{mgmt_zone}'): {snippet}"
            )
        return reasons
    if is_wan:
        # wan-zone: any change except the per-option tightenings (input or
        # forward set to DROP/REJECT) and the free-form logging options
        for change in group.changes:
            piece = change.line[:120]
            if change.option is None:
                reasons.append(f"wan-zone: WAN exposure: change to a wan zone (the section itself): {piece}")
                break
            if change.op == "-":
                reasons.append(f"wan-zone: WAN exposure: change to a wan zone ('{change.option}' deleted): {piece}")
                break
            value = change.value if change.value is not None else ""
            if change.option in ZONE_EXPOSURE_POLICY_OPTIONS:
                if value.upper() not in DROP_TARGETS:
                    reasons.append(f"wan-zone: WAN exposure: change to a wan zone ('{change.option}'='{value}' is not a DROP/REJECT tightening): {piece}")
                    break
            elif change.option not in WAN_ZONE_EXEMPT_OPTIONS:
                reasons.append(f"wan-zone: WAN exposure: change to a wan zone (option '{change.option}'): {piece}")
                break
        return reasons

    # zone-exposure: any other zone, new or existing
    new_word = "new zone " if group.is_new else "zone "
    for change in group.changes:
        if change.option in ZONE_EXPOSURE_POLICY_OPTIONS:
            piece = change.line[:120]
            if change.op == "-":
                reasons.append(f"zone-exposure: {new_word}'{label}' deletes {change.option} (the zone then follows defaults): {piece}")
                break
            if _is_accept(change.value):
                reasons.append(f"zone-exposure: {new_word}'{label}' sets {change.option}='{change.value}' (ACCEPT): {piece}")
                break
        if change.op != "-" and change.option in ZONE_EXPOSURE_CAPTURE_OPTIONS:
            reasons.append(f"zone-exposure: {new_word}'{label}' sets '{change.option}' (the diff cannot show what it captures): {change.line[:120]}")
            break
    if not reasons:
        # The router also fires when the staged network gains, over the
        # COMMITTED network, an interface of a wan-list zone; the committed
        # network is not on the host, so only the staged wan/wan6 names
        # count here (design 5.2 intended differences).
        for member in network:
            if member in WAN_NETWORK_NAMES:
                reasons.append(f"zone-exposure: {new_word}'{label}' lists the '{member}' network (a WAN network): {snippet}")
                break
    if not reasons and group.is_new:
        for option in ZONE_EXPOSURE_POLICY_OPTIONS:
            state, _ = group.option_state(option)
            if state != "set":
                reasons.append(f"zone-exposure: new zone '{label}' sets no {option} (the zone then follows defaults): {snippet}")
                break
    return reasons


def _forwarding_reasons(group: SectionGroup, mgmt_zone: str, wan_zones: tuple[str, ...]) -> list[str]:
    src_state, src = group.option_state("src")
    dest_state, dest = group.option_state("dest")
    snippet = group.changes[0].line[:120]
    reasons: list[str] = []
    # The router reads the committed src/dest too; for an existing section
    # whose src/dest the diff does not show they are unknown here, so the
    # reasons fire (fail safe: it may involve the mgmt zone / come from wan).
    if (src_state == "set" and src == mgmt_zone) or (dest_state == "set" and dest == mgmt_zone):
        reasons.append(f"forwarding-mgmt: forwarding involving the management zone '{mgmt_zone}': {snippet}")
    elif src_state == "unknown" or dest_state == "unknown":
        reasons.append(
            f"forwarding-mgmt: forwarding change on a forwarding whose src or dest the diff does not show "
            f"(it may involve the management zone '{mgmt_zone}'): {snippet}"
        )
    if src_state == "set" and (src in wan_zones or src == WILDCARD_SOURCE):
        reasons.append(f"wan-forwarding: forwarding from a wan zone ('{src}'): {snippet}")
    elif src_state == "unknown":
        reasons.append(f"wan-forwarding: forwarding whose src the diff does not show (it may come from a wan zone): {snippet}")
    return reasons


def _redirect_reasons(group: SectionGroup, wan_zones: tuple[str, ...]) -> list[str]:
    src_state, src = group.option_state("src")
    snippet = group.changes[0].line[:120]
    if src_state == "set" and src not in wan_zones and src != WILDCARD_SOURCE:
        return []
    if src_state == "set":
        return [f"wan-redirect: WAN exposure: redirect from a wan zone ('{src}'): {snippet}"]
    # a redirect with no src the host can see: a new redirect without src is
    # invalid staging anyway, an existing one may be from wan (the committed
    # src is not in the diff) -> fail safe
    return [f"wan-redirect: WAN exposure: redirect whose source zone is not shown (it may be wan): {snippet}"]


def _rule_reasons(group: SectionGroup, wan_zones: tuple[str, ...]) -> list[str]:
    src_state, src = group.option_state("src")
    if src_state == "absent":
        # a new rule shows every option: no src line means an output rule
        return []
    if src_state == "set" and src not in wan_zones and src != WILDCARD_SOURCE:
        return []
    snippet = group.changes[0].line[:120]
    # src is wan, '*' or unknown (an existing rule whose src the diff does
    # not show; the committed src is not on the host -> fail safe, it may be
    # from wan)
    target_state, target = group.option_state("target")
    fire = group.deleted or group.reordered
    if not fire:
        for change in group.changes:
            if change.option == "enabled" and change.op != "-" and change.value == "0":
                fire = True
                break
    if not fire:
        # target unset (a new rule) or ACCEPT fires; an UNKNOWN target (an
        # existing rule whose target is not in the diff) fires fail safe
        fire = target_state != "set" or _is_accept(target)
    if not fire:
        return []
    if src_state == "set":
        label = f"target '{target}'" if target_state == "set" else "no target"
        return [f"wan-rule: WAN exposure: rule from a wan zone ('{src}') with {label}: {snippet}"]
    return [f"wan-rule: WAN exposure: rule whose source zone is not shown (it may be wan): {snippet}"]


def _defaults_reasons(group: SectionGroup) -> list[str]:
    for change in group.changes:
        if change.option in ZONE_EXPOSURE_POLICY_OPTIONS and change.op != "-" and _is_accept(change.value):
            return [f"defaults-accept: firewall defaults sets {change.option}='{change.value}' (ACCEPT): {change.line[:120]}"]
    return []


def _group_reasons(
    group: SectionGroup,
    mgmt_interface: str,
    mgmt_zone: str,
    wan_zones: tuple[str, ...],
    deleted_values: Mapping[tuple[str, str, str], str | tuple[str, ...]] | None,
) -> list[str]:
    snippet = group.changes[0].line[:120]
    reasons: list[str] = []
    if group.config in MANAGEMENT_CONFIGS:
        reasons.append(f"mgmt-config: change to the {group.config} config (management access service): {snippet}")
    if group.config == "ucitrack":
        reasons.append(f"exec-config: change to the ucitrack config (it can restart services with other binaries): {snippet}")
    if group.config not in KNOWN_PACKAGES:
        # the config name itself is diff text; only the trailing line carries it
        reasons.append(f"unknown-package: change to a config no known package owns: {snippet}")

    section_type = group.resolved_type()

    if group.config == "network":
        named_mgmt = group.section == mgmt_interface
        fact_named_mgmt = (
            group.fact is not None
            and group.fact[1] is not None
            and group.fact[1] == mgmt_interface
        )
        if section_type is None:
            if named_mgmt or fact_named_mgmt:
                # a section the diff names like the mgmt interface, or whose
                # router fact names the mgmt interface even with no type, is
                # the mgmt interface (R2-POL-01)
                reasons.append(f"mgmt-interface: change to the management interface '{mgmt_interface}' (network.{group.section}): {snippet}")
            elif group.fact is not None or group.is_new:
                # the router looked at both views and found no type, OR the
                # diff's new-section line had a value the masker could only
                # render as a placeholder (`<masked>` / `<redacted:...>`);
                # in the latter case ``_groups`` left ``section_type`` as
                # None and ``is_new`` is set because the new-section line
                # was present.  Either way the policy cannot tell whether
                # the section is an interface, a bridge member or a route,
                # so it fails safe (the raw diff
                # ``network.br_auth='device'`` fires bridge-member; the
                # masked diff must also require approval).
                reasons.append(f"section-unidentified: network.{group.section} change; the diff does not show what the section is: {snippet}")
            # a facts-absent existing (non-new) named section of unknown
            # type stays free, as before
        elif section_type == "interface":
            if named_mgmt or fact_named_mgmt:
                reasons.append(f"mgmt-interface: change to the management interface '{mgmt_interface}' (network.{group.section}): {snippet}")
            elif group.fact is None and ANON_SECTION_RE.fullmatch(group.section):
                # fail-safe as before the router facts: an @interface[N] the
                # facts do not resolve may be the management interface
                reasons.append(
                    f"mgmt-interface: network change on an unidentified interface that may be the management interface '{mgmt_interface}': {snippet}"
                )
        elif section_type in BRIDGE_SECTION_TYPES:
            reasons.append(f"bridge-member: change to network.{group.section}, a '{section_type}' section (bridge/VLAN membership): {snippet}")
        elif section_type in ROUTE_SECTION_TYPES:
            # The router checks the committed `interface` too; it is not on
            # the host, so only the staged (diff) value counts here.
            state, interface = group.option_state("interface")
            if state == "set" and interface == mgmt_interface:
                reasons.append(f"mgmt-route: route for the management interface '{mgmt_interface}': {snippet}")
    elif group.config == "firewall":
        if section_type is None:
            reasons.append(
                f"section-unidentified: firewall.{group.section} change; the diff does not show what the section is "
                f"(it may be the management zone '{mgmt_zone}', a forwarding, a redirect or a rule from wan): {snippet}"
            )
        elif section_type == "zone":
            reasons.extend(_zone_reasons(group, mgmt_interface, mgmt_zone, wan_zones))
            if not _zone_names(group):
                reasons.append(
                    f"section-unidentified: firewall.{group.section} is a zone with no name the diff or the router facts can show "
                    f"(an unnamed zone escapes every name test): {snippet}"
                )
        elif section_type == "forwarding":
            reasons.extend(_forwarding_reasons(group, mgmt_zone, wan_zones))
        elif section_type == "redirect":
            reasons.extend(_redirect_reasons(group, wan_zones))
        elif section_type == "rule":
            reasons.extend(_rule_reasons(group, wan_zones))
        elif section_type == "defaults":
            reasons.extend(_defaults_reasons(group))
        elif section_type == "include":
            reasons.append(f"exec-include: change to firewall.{group.section}, an include section (it can run arbitrary scripts): {snippet}")
        else:
            reasons.append(
                f"firewall-type: firewall.{group.section} is of unknown type '{section_type}' "
                f"(only defaults/zone/forwarding/rule/redirect/include are known): {snippet}"
            )

    # per-option codes, every config
    for change in group.changes:
        if change.option is None:
            continue
        piece = change.line[:120]
        if change.option in EXEC_OPTION_NAMES.get(group.config, ()):
            reasons.append(f"exec-option: the '{change.option}' option in config {group.config} can run commands or write files: {piece}")
        if group.config == "upnpd" and change.option in UPNP_OPTIONS and change.op != "-" and (change.value is None or change.value == "1"):
            reasons.append(f"upnp-on: upnpd {change.option} switched to 1: {piece}")

    # path-option: the values the change itself sets; deleted values fail safe
    # unless the committed view of a named section supplies their exact value.
    if group.deleted:
        # every option of a deleted section had committed values the diff
        # cannot show -> fail safe (the router reads the committed view)
        reasons.append(f"path-option: the section is deleted and the diff cannot show the values its options held: {snippet}")
    else:
        for change in group.changes:
            if change.option is None:
                continue
            if change.op == "-":
                key = (group.config, change.section, change.option)
                if deleted_values is None or key not in deleted_values:
                    # the deleted option's committed value is not in the diff -> fail safe
                    reasons.append(f"path-option: the deleted option '{change.option}' may have held a path (the committed value is not in the diff): {change.line[:120]}")
                    break
                value = deleted_values[key]
                items = (value,) if isinstance(value, str) else value
                if not isinstance(items, tuple) or not all(isinstance(item, str) for item in items):
                    reasons.append(f"path-option: the deleted option '{change.option}' may have held a path (the committed value is not in the diff): {change.line[:120]}")
                    break
                bad_token = next(
                    (
                        token
                        for item in items
                        for token in item.split()
                        if _path_is_bad(token)
                    ),
                    None,
                )
                if bad_token is not None:
                    reasons.append(f"path-option: the deleted option '{change.option}' held a path ('{bad_token}'): {change.line[:120]}")
                    break
                continue
            if change.value is None:
                # an option renamed to this name: its staged value is not in the diff -> fail safe
                reasons.append(f"path-option: the renamed option '{change.option}' may hold a path (its staged value is not in the diff): {change.line[:120]}")
                break
            for token in change.value.split():
                if _path_is_bad(token):
                    reasons.append(f"path-option: '{change.option}' holds a path ('{token}'): {change.line[:120]}")
                    break
            else:
                continue
            break

    if group.config == "system" and section_type == "timeserver":
        # the router reads the staged view (enable_server '1' and no staged
        # interface); the host sees only the diff, so only a diff-set
        # enable_server counts
        state, value = group.option_state("enable_server")
        iface_state, iface = group.option_state("interface")
        if state == "set" and value == "1" and not (iface_state == "set" and iface):
            reasons.append(f"ntp-server-open: the timeserver answers on every interface (enable_server=1, no interface): {snippet}")

    return reasons


def _index_shift_reasons(groups: dict[tuple[str, str], SectionGroup]) -> list[str]:
    """Finding F-D, on the diff lines alone (the router computes it too).

    A ``@TYPE[N]`` selector line next to a structural line (delete, rename,
    reorder or new section) of the same (config, type) may name a different
    section in the staged view than in the committed one; the resolved
    section is not trustworthy, so the change fails safe.
    """
    totals: dict[tuple[str, str], int] = {}
    structural: dict[tuple[str, str], int] = {}
    for group in groups.values():
        group_type = group.resolved_type() or ""
        for change in group.changes:
            match = ANON_SECTION_RE.fullmatch(change.section)
            selector = match.group(1) if match else ""
            is_structural = change.option is None and change.op in ("", "-", "@", "^")
            if not selector and not is_structural:
                continue
            key = (group.config, selector or group_type)
            totals[key] = totals.get(key, 0) + 1
            if is_structural:
                structural[key] = structural.get(key, 0) + 1
    for group in groups.values():
        for change in group.changes:
            match = ANON_SECTION_RE.fullmatch(change.section)
            if match is None:
                continue
            key = (group.config, match.group(1))
            if structural.get(key, 0) > 0 and totals.get(key, 0) >= 2:
                return [
                    f"section-unidentified: an @{match.group(1)}[N] selector next to a structural change of the same type may name "
                    f"a different section before and after the change: {change.line[:120]}"
                ]
    return []


def classify(
    device: Any,
    uci_batch: str,
    diff: str,
    section_facts: Mapping[tuple[str, str], tuple[str | None, str | None]] | None = None,
    deleted_values: Mapping[tuple[str, str, str], str | tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    """Return {'requires_approval': bool, 'risk': 'critical'|'low', 'reasons': [str]}.

    ``device`` needs the inventory fields ``profile`` ('lab' | 'prod'),
    ``mgmt_interface``, ``mgmt_zone`` and optionally ``wan_zones`` (default
    ``("wan",)``; a bare SimpleNamespace with profile/mgmt_interface/
    mgmt_zone still works).  ``section_facts`` maps ``(config, section)`` to
    the router's ``(type, name)`` pair for that section (``-``/None = none),
    from the seal's ``section`` lines.  Raises ``ValueError`` for a batch
    that is not staging verbs only, or for invalid device settings
    (inventory errors, not silent defaults).
    """
    profile, mgmt_interface, mgmt_zone, wan_zones = _device_settings(device)
    _require_staging_verbs(uci_batch)
    if section_facts is not None and not isinstance(section_facts, Mapping):
        raise ValueError("section_facts must be a mapping from (config, section) to (type, name) or None")
    if deleted_values is not None and not isinstance(deleted_values, Mapping):
        raise ValueError("deleted_values must be a mapping from (config, section, option) to committed values or None")
    reasons: list[str] = []
    critical = False
    writes = any(line.strip() and not line.strip().startswith("#") for line in uci_batch.splitlines())
    changes = [change for change in (parse_diff_line(line) for line in diff.splitlines()) if change is not None]
    if changes:
        writes = True
    for change in changes:
        if not change.parsed:
            reasons.append(f"unparsed-change: unparsed staged change requires approval: {change.line[:120]}")
            critical = True
    parsed_changes = [change for change in changes if change.parsed]
    groups = _groups(parsed_changes, section_facts)
    for group in groups.values():
        for reason in _group_reasons(
            group, mgmt_interface, mgmt_zone, wan_zones, deleted_values
        ):
            reasons.append(reason)
            critical = True
    for reason in _index_shift_reasons(groups):
        reasons.append(reason)
        critical = True
    if profile == "prod" and writes:
        reasons.append(PROD_REASON)
    reasons = list(dict.fromkeys(reasons))
    return {
        "requires_approval": bool(reasons),
        "risk": RISK_CRITICAL if critical else RISK_LOW,
        "reasons": reasons,
    }
