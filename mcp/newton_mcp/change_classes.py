"""Classify a staged UCI change into the kinds of change a grant can cover.

Scoped grants: the owner may allow named kinds
of change on a device until a time.  Newton, never the agent, decides
what a staged change IS; this module reads the staged config lines and
nothing else, so a change cannot be talked into a class by describing
it.

Two questions are answered here, and they are not the same question:

* ``high`` -- is this change HIGH (internet exposure, management access,
  an option that runs commands)?  A grant never covers a HIGH change.
* ``grantable`` -- is EVERY line of the change explained by one of the
  four grantable classes, with no other verb, no disallowed ``add`` and
  no placeholder left in the batch?

Both answers are deterministic rules over the staged lines.  There is no
model, no prose and no agent input anywhere in this module.

The classifier fails closed.  A section whose type the batch does not
state cannot be checked against the class list, so its options count as
unexplained and the change is not grantable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from . import touched
from .consequences import Facts, Types, _sections, _types, _values


# The four kinds of change a grant may cover, in the order they are
# offered to the owner.
GRANTABLE_CLASSES: tuple[str, ...] = (
    "dhcp-reservations",
    "dns",
    "hostname",
    "wifi-name-key",
)

# The plain phrase each class is named by in a dialog.  The owner reads
# these words, so they say what the class does, not what it is called.
CLASS_LABELS: dict[str, str] = {
    "dhcp-reservations": "DHCP reservations",
    "dns": "DNS settings",
    "hostname": "the router name",
    "wifi-name-key": "Wi-Fi name and password",
}

# The fixed words a HIGH reason is reported as.  They are the same on
# every run so the owner can learn them.
REASON_INTERNET_EXPOSURE = "internet-exposure"
REASON_MANAGEMENT_ACCESS = "management-access"
REASON_RUNS_COMMANDS = "runs-commands"

# The verbs that stage a change.  Anything else (delete, rename,
# reorder, revert and every unknown verb) is an "other verb", and a
# batch with one is never grantable.
_STAGING_VERBS = frozenset({"set", "add_list", "del_list", "add"})

# The only ``add`` forms a grant may cover: they create a section of a
# type the grantable classes know, with no option of their own.
_ALLOWED_ADDS = frozenset({("dhcp", "host"), ("dhcp", "domain")})

# The configs whose change is management access, and the configs whose
# change is internet exposure.
_MANAGEMENT_CONFIGS = frozenset({"uhttpd", "dropbear", "rpcd"})
_EXPOSURE_CONFIGS = frozenset({"upnpd", "miniupnpd"})

# A delete of one of these paths is management access as well: it takes
# a rule or a way in away.
_MANAGEMENT_DELETES = _MANAGEMENT_CONFIGS | frozenset({"firewall"})

# The option names that run a command on the router.  One of them in a
# change is HIGH whatever else the change does.
_COMMAND_OPTIONS = frozenset(
    {
        "dhcp_script",
        "script",
        "init",
        "hotplug",
        "exec",
        "cmd",
        "command",
        "path",
        "include",
        "lease_script",
        "dhcpscript",
        "userscript",
    }
)

# A placeholder left in the batch means the change is not finished, so
# it is never grantable.
_PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}")

# The wildcard section type: a class that does not constrain the type
# of its section (the router name lives in any section of ``system``).
_ANY_TYPE = "*"


@dataclass(frozen=True)
class _ClassSpec:
    """What one grantable class allows.

    ``options_by_type`` maps a section type to the options the class
    allows on it; the key ``"*"`` means the class does not constrain the
    section type.
    """

    name: str
    config: str
    options_by_type: Mapping[str, frozenset[str]]


_CLASS_SPECS: tuple[_ClassSpec, ...] = (
    _ClassSpec(
        "dhcp-reservations",
        "dhcp",
        {
            "host": frozenset(
                {"name", "mac", "ip", "hostname", "dns", "leasetime", "tag"}
            )
        },
    ),
    _ClassSpec(
        "dns",
        "dhcp",
        {
            "dnsmasq": frozenset({"server", "address", "local", "domain"}),
            "domain": frozenset({"name", "ip"}),
        },
    ),
    _ClassSpec(
        "hostname",
        "system",
        {"*": frozenset({"hostname"})},
    ),
    _ClassSpec(
        "wifi-name-key",
        "wireless",
        {"wifi-iface": frozenset({"ssid", "key"})},
    ),
)


@dataclass(frozen=True)
class Classification:
    """What a staged change is.

    ``classes`` is the set of grantable classes the change touches (it
    says what the change IS, even when the change as a whole is not
    grantable).  ``grantable`` says the change may be covered by a grant
    that allows those classes.  ``high`` and ``high_reasons`` say the
    change is HIGH, which no grant ever covers.
    """

    classes: frozenset[str]
    grantable: bool
    high: bool
    high_reasons: tuple[str, ...]


_NOTHING = Classification(frozenset(), False, False, ())


def types_of(
    facts: Facts, extra: Mapping[tuple[str, str], str] | None = None
) -> Types:
    """The type of every section the change touches.

    The batch knows the type of the sections it creates.  The router
    knows the type of the sections it already holds, and a change may
    touch an option of a section the batch never creates.

    The ROUTER wins: a section the router holds is what it is, and a
    batch that says another type for it does not get to change that.
    A batch that disagrees with the router about the type of a section
    leaves the section untyped, so nothing explains the change and it
    is never grantable.
    """
    types = _types(facts)
    if not extra:
        return types
    merged: Types = {
        key: value for key, value in extra.items() if isinstance(value, str)
    }
    for key, value in types.items():
        if key not in merged:
            # a section the router does not hold: the batch's own type
            # is the only one there is
            merged[key] = value
    return merged


def types_of_record(record: Mapping[str, Any]) -> Types:
    """The types of the sections a plan record carries.

    A change of a section the router already holds has no class without
    the type the router holds, so the plan carries those types and this
    rebuilds the map from them.  The record holds them as
    ``config.section`` keys.
    """
    raw = record.get("section_types")
    if not isinstance(raw, Mapping):
        return {}
    types: Types = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        config, _, section = key.partition(".")
        if not config or not section:
            continue
        types[(config, section)] = value
    return types


def _candidate_types(config: str, classes: set[str]) -> list[str]:
    """The types the given classes allow on one config.

    A class that does not constrain the type of its section (the
    router name lives in any section of ``system``) allows the
    wildcard type.
    """
    candidates: list[str] = []
    for spec in _CLASS_SPECS:
        if spec.name not in classes or spec.config != config:
            continue
        for section_type in spec.options_by_type:
            if section_type not in candidates:
                candidates.append(section_type)
    return candidates


def optimistic_types(
    uci_batch: str, classes: Iterable[str]
) -> Types:
    """The type every section of a batch would need to be grantable.

    The class of a change of a section the router already holds needs
    the type the router holds, and the router is not read yet.  This
    map says what the type WOULD have to be: the types the given
    classes allow on the config of that section.

    Only the sections the batch touches are in the map.  A section
    with no type that explains all of its facts is left out, so a
    change that no type could explain is never grantable with this
    map.
    """
    if not isinstance(uci_batch, str):
        return {}
    wanted = {str(name) for name in classes}
    if not wanted:
        return {}
    per_section: dict[tuple[str, str], list[Any]] = {}
    for fact in touched._parse_batch_facts(uci_batch):
        per_section.setdefault((fact.cfg, fact.section), []).append(fact)
    types: Types = {}
    for key, section_facts in per_section.items():
        for candidate in _candidate_types(key[0], wanted):
            if all(
                _explaining_classes(
                    fact.cfg, fact.option, fact.value, candidate
                )
                for fact in section_facts
            ):
                types[key] = candidate
                break
    return types


def uses_a_list_verb(uci_batch: str) -> bool:
    """Does the batch use a list verb?

    A list verb (``add_list`` / ``del_list``, and the UCI sugar
    ``set opt+=`` / ``set opt-=``) has no shape in the transaction
    engine: such a change is an owner script, and a grant covers
    only the changes Newton applies itself.
    """
    if not isinstance(uci_batch, str):
        return False
    for raw in uci_batch.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = touched._split_batch_words(line)
        if len(words) < 2:
            continue
        verb = words[0]
        if verb in ("add_list", "del_list"):
            return True
        if verb != "set":
            continue
        path, _, _value = words[1].partition("=")
        parsed = touched._parse_batch_path_with_marker(path)
        if parsed is None:
            continue
        if parsed[3] in ("+", "-"):
            return True
    return False


def classify(
    uci_batch: str, types: Mapping[tuple[str, str], str] | None = None
) -> Classification:
    """Classify a staged UCI batch.

    ``types`` is the type of the sections the router holds now, for
    the sections the batch does not create.  Without it a change of an
    option of an existing section has no class at all.

    Never raises: odd input (a non-string, junk lines, an unfinished
    batch) classifies as "not grantable", which is the safe answer.
    """
    if not isinstance(uci_batch, str):
        return _NOTHING
    facts = touched._parse_batch_facts(uci_batch)
    section_types = types_of(facts, types)
    lines = _change_lines(uci_batch)
    add_lines = [words for words in lines if words[0] == "add"]
    other_verbs = [words for words in lines if words[0] not in _STAGING_VERBS]
    add_facts = [
        added for added in (_add_fact(words) for words in add_lines)
        if added is not None
    ]
    delete_configs = {
        _path_config(words[1])
        for words in lines
        if words[0] == "delete" and len(words) > 1
    }
    reasons = _high_reasons(facts, section_types, add_facts, delete_configs)
    classes, explained = _classes_of(facts, section_types, add_facts)
    grantable = (
        bool(classes)
        and explained
        and not other_verbs
        and not _bad_add(add_lines)
        and not reasons
        and _PLACEHOLDER_RE.search(uci_batch) is None
    )
    return Classification(
        classes=frozenset(classes),
        grantable=grantable,
        high=bool(reasons),
        high_reasons=tuple(sorted(reasons)),
    )


#: The section address uci writes: ``@type[index]``.
_ANON_ADDRESS_RE = re.compile(r"^@([A-Za-z0-9_-]{1,32})\[(-?[0-9]{1,3}|\*)\]$")


def _section_type_of(
    section_types: Types, config: str, section: str
) -> str | None:
    """The type of a section a batch names.

    A named section's type is the router's own; an anonymous address
    carries its type in the address itself.
    """
    section_type = section_types.get((config, section))
    if section_type is None:
        address = _ANON_ADDRESS_RE.fullmatch(section)
        if address is not None:
            section_type = address.group(1)
    return section_type


def classes_of_deletes(
    uci_batch: str, types: Mapping[tuple[str, str], str] | None = None
) -> frozenset[str]:
    """The classes the delete and del_list lines of a batch touch.

    A delete takes a setting away, so it is a change OF that setting:
    the class it belongs to is the class the setting belongs to.  The
    router's own types say which class that is: the type of a named
    section comes from the router, and an anonymous address carries its
    type in the address itself.

    A delete the batch takes back again is not a change: a batch that
    adds a value and removes it again leaves the list as it was, and a
    batch that creates a section and deletes it again leaves nothing.

    The classes of the other lines are NOT in here: the caller adds
    them.  A batch that only takes settings away has classes here, and
    a batch that only sets them has none.

    This never changes what a grant covers: ``classify`` still decides
    that on its own.
    """
    if not isinstance(uci_batch, str):
        return frozenset()
    facts = touched._parse_batch_facts(uci_batch)
    section_types = types_of(facts, types)
    matched: set[str] = set()
    # the values this batch added and has not taken away again
    added: set[tuple[str, str, str, str]] = set()
    # the sections this batch created
    created: set[tuple[str, str]] = set()
    for words in _change_lines(uci_batch):
        verb = words[0]
        if len(words) < 2:
            continue
        path_text, _, raw_value = words[1].partition("=")
        parsed = touched._parse_batch_path_with_marker(path_text)
        if parsed is None:
            continue
        config, section, option, marker = parsed
        if verb == "set" and marker == "+":
            verb = "add_list"
        elif verb == "set" and marker == "-":
            verb = "del_list"
        value = touched._unquote(raw_value)
        if verb == "set":
            if option is None:
                # a set of a section the router already has does not
                # create it: its later delete is still a delete
                if _section_type_of(section_types, config, section) is None:
                    created.add((config, section))
                added = {
                    item for item in added
                    if not (item[0] == config and item[1] == section)
                }
            else:
                # a plain set resets the list it writes
                added = {
                    item for item in added
                    if not (item[0] == config and item[1] == section
                            and item[2] == option)
                }
            continue
        if verb == "add_list":
            if option is not None:
                added.add((config, section, option, value))
            continue
        if verb == "del_list":
            if option is None:
                continue
            key = (config, section, option, value)
            if key in added:
                # the batch added this value and takes it away again
                added.discard(key)
                continue
            matched |= _explaining_classes(
                config,
                option,
                None,
                _section_type_of(section_types, config, section),
            )
            continue
        if verb == "delete":
            if option is None:
                if (config, section) in created:
                    # the batch creates the section and takes it away
                    continue
                matched |= _explaining_classes(
                    config,
                    None,
                    _section_type_of(section_types, config, section),
                    None,
                )
                continue
            matched |= _explaining_classes(
                config,
                option,
                None,
                _section_type_of(section_types, config, section),
            )
    return frozenset(matched)


def _change_lines(uci_batch: str) -> list[list[str]]:
    """The change lines of a batch, as words.

    A change line is a non-blank line that is not a comment; anything
    else in the batch is not a change.
    """
    lines: list[list[str]] = []
    for raw in uci_batch.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = touched._split_batch_words(line)
        if not words:
            continue
        lines.append(words)
    return lines


def _path_config(path: str) -> str:
    """The config a UCI path names: the part before the first dot."""
    return path.split(".", 1)[0]


def _bad_add(add_lines: list[list[str]]) -> bool:
    """Is there an ``add`` line that a grant may not cover?"""
    for words in add_lines:
        if len(words) != 3 or (words[1], words[2]) not in _ALLOWED_ADDS:
            return True
    return False


def _add_fact(words: list[str]) -> tuple[str, str] | None:
    """An ``add`` line as the section it creates: ``(config, type)``."""
    if len(words) < 3:
        return None
    config, section_type = words[1], words[2]
    if not config or not section_type:
        return None
    return (config, section_type)


def _high_reasons(
    facts: Facts,
    types: Types,
    add_facts: list[tuple[str, str]],
    delete_configs: set[str],
) -> set[str]:
    """Why a change is HIGH, as a set of fixed reason words."""
    reasons: set[str] = set()
    touched_configs = {fact.cfg for fact in facts}
    touched_configs.update(config for config, _section_type in add_facts)
    touched_configs.update(delete_configs)
    if touched_configs & _EXPOSURE_CONFIGS:
        reasons.add(REASON_INTERNET_EXPOSURE)
    if touched_configs & _MANAGEMENT_CONFIGS:
        reasons.add(REASON_MANAGEMENT_ACCESS)
    if delete_configs & _MANAGEMENT_DELETES:
        reasons.add(REASON_MANAGEMENT_ACCESS)
    for config, section in _sections(types, "firewall", "redirect"):
        reasons.add(REASON_INTERNET_EXPOSURE)
    for config, section in _sections(types, "firewall", "rule"):
        if "wan" in _values(facts, config, section, "src") and (
            "ACCEPT" in _values(facts, config, section, "target")
        ):
            reasons.add(REASON_INTERNET_EXPOSURE)
    for config, section in _sections(types, "firewall", "zone"):
        if "wan" in _values(facts, config, section, "name") and (
            "ACCEPT" in _values(facts, config, section, "input")
            or "ACCEPT" in _values(facts, config, section, "forward")
        ):
            reasons.add(REASON_INTERNET_EXPOSURE)
    # An option set on an EXISTING firewall section (its type is not in the
    # batch) can open the router to the internet too: treat ACCEPT as the
    # value of target/input/forward in the firewall as exposure.
    for fact in facts:
        if (
            fact.cfg == "firewall"
            and fact.option in ("target", "input", "forward")
            and fact.value == "ACCEPT"
        ):
            reasons.add(REASON_INTERNET_EXPOSURE)
    for config, section in _sections(types, "firewall", "include"):
        reasons.add(REASON_RUNS_COMMANDS)
    for fact in facts:
        if fact.option is not None and fact.option in _COMMAND_OPTIONS:
            reasons.add(REASON_RUNS_COMMANDS)
    return reasons


def _classes_of(
    facts: Facts,
    types: Types,
    add_facts: list[tuple[str, str]],
) -> tuple[set[str], bool]:
    """The classes a change touches, and whether every line is explained.

    A line is explained when a class allows it: the config, the section
    type and the option must all be on the class's list.
    """
    classes: set[str] = set()
    explained = True
    for fact in facts:
        matched = _explaining_classes(
            fact.cfg,
            fact.option,
            fact.value,
            types.get((fact.cfg, fact.section)),
        )
        if not matched:
            explained = False
        classes |= matched
    for config, section_type in add_facts:
        matched = _explaining_classes(config, None, section_type, None)
        if not matched:
            explained = False
        classes |= matched
    return classes, explained


def _explaining_classes(
    config: str,
    option: str | None,
    value: str | None,
    section_type: str | None,
) -> set[str]:
    """The classes that allow one line of a change.

    ``option`` is None for a section-creating line, where ``value`` is
    the type of the section; for an option line ``section_type`` is the
    type of the section the option sits in, when the batch states it.
    """
    matched: set[str] = set()
    for spec in _CLASS_SPECS:
        if config != spec.config:
            continue
        if option is None:
            # A section-level line: its value is the section type.  On a
            # section the router already holds it CHANGES the type (a
            # radio made an interface), and the router's type wins: a
            # batch that says another type for a section the router
            # holds explains nothing.  Only the creations a grant may
            # make count, and never through the wildcard type.
            if section_type is not None and section_type != value:
                continue
            if (
                value in spec.options_by_type
                and (config, value) in _ALLOWED_ADDS
            ):
                matched.add(spec.name)
            continue
        allowed = spec.options_by_type.get(section_type)
        if allowed is None:
            allowed = spec.options_by_type.get(_ANY_TYPE)
        if allowed is not None and option in allowed:
            matched.add(spec.name)
    return matched
