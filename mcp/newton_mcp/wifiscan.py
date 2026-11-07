"""Wi-Fi survey summary for the router's own radio.

Pure functions: no I/O, no device access, no network.  The MCP server
hands in the parsed scan results, the router's own SSIDs, the router's own
channel and the router's own BSSIDs; this module returns the channel
counts, the strongest signal per channel and the look-alike findings.

Two rules hold everywhere in this module:

* a BSSID never leaves it, and
* a neighbour SSID only ever leaves it inside a look-alike finding.

Both SSIDs of a look-alike are device-originated text, so both go through
the untrusted envelope, and the envelope delimiters inside them are
neutralised first (design 04 rule 3): a name that carries
``</untrusted-device-data>`` must not be able to close the envelope it
sits in.

The look-alike rules, in the order they are applied:

* (a) ``homoglyph``: the folded names are equal and the raw names differ.
* (a2) ``homoglyph``: the names differ only by invisible characters: a
  control, a format or a space-separator character (a tab, a no-break
  space, a zero-width space).  Such a clone folds to the own name and
  reads as the own name on a phone, so it is reported.  A difference of
  plain ASCII spaces alone is the documented non-finding: that is the
  same name with a space in it.
* (d) ``mixed_script``: the seen name mixes scripts and its Latin-only
  skeleton matches the own name.  A script mix is a deliberate deception,
  so it is reported as one and not as a typo.
* (b) ``typo``: the own name's fold is at least six characters and the
  Damerau-Levenshtein distance is one (two from twelve characters).  A
  pair that is identical once the whitespace is gone is not a typo: it is
  the same name, and rule (a) already reports the byte-identical case.
* (c) ``same_ssid_other_ap``: the names are byte-identical and the seen
  BSSID is not the router's own.  The rule needs the router's own BSSID;
  when the router does not report one (the radio is off) the rule is
  skipped and the summary says so.

Out of scope: an own name with non-Latin letters.  The Latin-only
skeleton of rule (d) has no Latin name to imitate, so such an own name
is compared byte and fold only.  An all-Cyrillic clone of an all-Cyrillic
own name is therefore out of scope: the typo rule reports it when the own
name is at least six characters long, and nothing reports it when it is
shorter.  The byte-identical rule (c) still applies to such an own name.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from typing import Any

from . import envelope as envelope_module


# The confusable table is FIXED and ordered: the multi-character rules run
# first, so "rn" becomes "m" and not "r" plus "n"; the single-character
# rules run after, in the order below.  The order is part of the contract.
CONFUSABLES: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "l"),
    ("i", "l"),
    ("|", "l"),
    ("5", "s"),
)

# The non-Latin letters that imitate a Latin one.  The table maps the
# Cyrillic or Greek letter to the Latin letter the eye reads; it builds
# the "Latin-only skeleton" of a mixed-script name (rule (d)).
SCRIPT_LOOKALIKES: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0445": "x",  # х
    "\u0443": "y",  # у
    "\u0456": "i",  # і
    "\u0455": "s",  # ѕ
    "\u0458": "j",  # ј
    "\u04bb": "h",  # һ
    "\u043a": "k",  # к
    "\u043c": "m",  # м
    "\u0442": "t",  # т
    "\u0432": "b",  # в
    "\u043d": "n",  # н
    "\u0461": "v",  # ѵ
    # Greek
    "\u03b1": "a",  # α
    "\u03b5": "e",  # ε
    "\u03bf": "o",  # ο
    "\u03c1": "p",  # ρ
    "\u03c7": "x",  # χ
    "\u03b3": "y",  # γ
    "\u03b9": "i",  # ι
    "\u03c3": "s",  # σ
    "\u03ba": "k",  # κ
    "\u03bc": "m",  # μ
    "\u03c4": "t",  # τ
    "\u03b2": "b",  # β
    "\u03b7": "n",  # η
    "\u03bd": "v",  # ν
    "\u03f2": "c",  # ϲ
}

BAND_2G = "2.4 GHz"
BAND_5G = "5 GHz"
# At most ten look-alike findings, the strongest first: a list the owner
# can read in one go.
MAX_FINDINGS = 10
# A channel is crowded when at least this many OTHER networks sit in the
# window (2.4 GHz: within four channels; 5 GHz: the primary channel).
CROWDED_NETWORKS = 4
# The typo rule needs an own name of at least this many characters, and
# allows a second edit from this many characters on.
TYPO_MIN_LENGTH = 6
TYPO_SECOND_EDIT_LENGTH = 12
# The categories of the characters that read as nothing: the control, the
# format and the space-separator ones.  A name that differs from another
# one only by such characters is the same name to the eye.
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Zs")
SAME_NAME_CHECK_RAN = "same-name-other-AP check ran"
SAME_NAME_CHECK_UNAVAILABLE = (
    "same-name-other-AP check unavailable while the radio is off"
)

_RADIO_NAME_RE = re.compile(r"^radio[0-9]{1,2}$")
_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
_IWINFO_BSSID_RE = re.compile(
    r"Access Point:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
)
_UCI_LINE_RE = re.compile(
    r"^wireless\.(?P<section>[^=]+?)(?:\.(?P<option>[^=]+))?=(?P<value>.*)$"
)
_UCI_UNESCAPE_RE = re.compile(r"\\(.)")
# The options that make a section a wireless interface rather than a radio.
_IFACE_OPTIONS = frozenset({"ssid", "mode", "device", "ifname"})
# The values uci accepts for a disabled option.
_DISABLED_VALUES = frozenset({"1", "true", "yes", "on"})


def _without_spaces(text: str) -> str:
    """The text without any whitespace."""
    return "".join(text.split())


def fold(text: str) -> str:
    """The folded form of a network name.

    NFKC, then case folded, then the invisible characters (control,
    zero-width, format) dropped, then the fixed confusable table.  The
    whitespace stays: rule (a) compares the folded names as they are, so
    "V irgin" and "virgin" are different names.
    """
    normalised = unicodedata.normalize("NFKC", text)
    folded = normalised.casefold()
    visible = "".join(
        character
        for character in folded
        if unicodedata.category(character) not in ("Cc", "Cf")
    )
    for pattern, replacement in CONFUSABLES:
        visible = visible.replace(pattern, replacement)
    return visible


def fold_without_spaces(text: str) -> str:
    """The folded name without any whitespace."""
    return _without_spaces(fold(text))


def damerau_distance(left: str, right: str) -> int:
    """The Damerau-Levenshtein distance (optimal string alignment).

    An adjacent transposition counts as one edit, so "abcdfe" is one edit
    away from "abcdef".
    """
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous_previous = [0] * (len(right) + 1)
    previous = list(range(len(right) + 1))
    for index, left_character in enumerate(left, start=1):
        current = [index] + [0] * len(right)
        for position, right_character in enumerate(right, start=1):
            cost = 0 if left_character == right_character else 1
            current[position] = min(
                previous[position] + 1,
                current[position - 1] + 1,
                previous[position - 1] + cost,
            )
            if (
                index > 1
                and position > 1
                and left_character == right[position - 2]
                and left[index - 2] == right_character
            ):
                current[position] = min(
                    current[position], previous_previous[position - 2] + 1
                )
        previous_previous = previous
        previous = current
    return previous[len(right)]


def _is_outside_latin(character: str) -> bool:
    """True for a letter that is not a Latin letter."""
    if not character.isalpha():
        return False
    try:
        name = unicodedata.name(character)
    except ValueError:
        return True
    return not name.startswith("LATIN")


def latin_skeleton(text: str) -> str:
    """The name with every non-Latin letter replaced by its Latin look-alike."""
    pieces: list[str] = []
    for character in text:
        if _is_outside_latin(character):
            pieces.append(SCRIPT_LOOKALIKES.get(character, character))
        else:
            pieces.append(character)
    return "".join(pieces)


def _is_mixed_script(seen_ssid: str, own_ssid: str, own_compact: str) -> bool:
    """True when the seen name mixes scripts and imitates the own name.

    The Latin-only skeleton is compared with the own name, so the rule
    needs a Latin own name to imitate: an own name with a non-Latin
    letter is compared byte and fold only (see the module header).  Below
    the typo length floor the skeleton must equal the own fold exactly.
    """
    if not any(_is_outside_latin(character) for character in seen_ssid):
        return False
    if any(_is_outside_latin(character) for character in own_ssid):
        return False
    skeleton = _without_spaces(fold(latin_skeleton(seen_ssid.casefold())))
    if not skeleton:
        return False
    if skeleton == own_compact:
        return True
    if len(own_compact) < TYPO_MIN_LENGTH:
        return False
    return damerau_distance(skeleton, own_compact) <= 1


def _invisible_difference(seen: str, own: str) -> set[str]:
    """The invisible characters the two names differ by."""
    seen_counts = Counter(
        character
        for character in seen
        if unicodedata.category(character) in INVISIBLE_CATEGORIES
    )
    own_counts = Counter(
        character
        for character in own
        if unicodedata.category(character) in INVISIBLE_CATEGORIES
    )
    difference = seen_counts - own_counts
    difference.update(own_counts - seen_counts)
    return set(difference)


def _differs_only_by_invisible(seen: str, own: str) -> bool:
    """True when the two names differ only by invisible characters.

    A difference of plain ASCII spaces alone is not a clone: that is the
    documented non-finding (the same name with a space in it), so it does
    not fire here either.
    """
    if seen == own:
        return False
    if fold_without_spaces(seen) != fold_without_spaces(own):
        return False
    difference = _invisible_difference(seen, own)
    if not difference:
        return False
    return any(character != " " for character in difference)


def classify_lookalike(
    *,
    seen_ssid: str,
    seen_bssid: str,
    own_ssid: str,
    own_bssids: frozenset[str] | set[str],
) -> str | None:
    """The rule that fires for one (seen, own) pair, or None.

    ``own_bssids`` is the router's own BSSID set; an empty set means the
    router did not report one, and rule (c) is then skipped.
    """
    if seen_ssid == own_ssid:
        # The names are byte-identical: only rule (c) can apply.
        if not own_bssids:
            return None
        if seen_bssid in own_bssids:
            return None
        return "same_ssid_other_ap"
    seen_fold = fold(seen_ssid)
    own_fold = fold(own_ssid)
    if seen_fold == own_fold and _without_spaces(seen_ssid) != _without_spaces(
        own_ssid
    ):
        return "homoglyph"
    if _differs_only_by_invisible(seen_ssid, own_ssid):
        return "homoglyph"
    seen_compact = _without_spaces(seen_fold)
    own_compact = _without_spaces(own_fold)
    if _is_mixed_script(seen_ssid, own_ssid, own_compact):
        return "mixed_script"
    if len(own_compact) >= TYPO_MIN_LENGTH:
        limit = 2 if len(own_compact) >= TYPO_SECOND_EDIT_LENGTH else 1
        distance = damerau_distance(seen_compact, own_compact)
        if 1 <= distance <= limit:
            return "typo"
    return None


def band_of_channel(channel: int) -> str:
    """The band a channel belongs to."""
    return BAND_2G if channel <= 14 else BAND_5G


def _band_order(band: str) -> int:
    return 0 if band == BAND_2G else 1


def channel_crowded_finding(
    *,
    radio: str,
    own_channel: int | None,
    results: list[dict[str, Any]],
    own_bssids: frozenset[str] | set[str],
) -> dict[str, Any] | None:
    """The crowded-channel finding, or None.

    On 2.4 GHz every channel within four of the router's own counts; on
    5 GHz only the primary channel does.  The router's own AP is not a
    neighbour.
    """
    if own_channel is None:
        return None
    band = band_of_channel(own_channel)
    if band == BAND_2G:
        low, high = own_channel - 4, own_channel + 4
    else:
        low = high = own_channel
    others = [
        result
        for result in results
        if low <= result["channel"] <= high and result["bssid"] not in own_bssids
    ]
    if len(others) < CROWDED_NETWORKS:
        return None
    return {
        "finding": "channel_crowded",
        "radio": radio,
        "band": band,
        "channel": own_channel,
        "networks": len(others),
        "window": f"{low}-{high}",
    }


def _enveloped(source: str, text: str) -> dict[str, str]:
    """The SSID inside the untrusted envelope, with the delimiters escaped."""
    return envelope_module.envelope(
        source, envelope_module.escape_delimiters(text)
    )


def lookalike_findings(
    *,
    results: list[dict[str, Any]],
    own_ssids: list[str],
    own_bssids: frozenset[str] | set[str],
    source: str,
) -> list[dict[str, Any]]:
    """The look-alike findings, the strongest first, at most ten."""
    findings: list[dict[str, Any]] = []
    for result in results:
        seen_ssid = result["ssid"]
        if not seen_ssid:
            continue
        seen_bssid = result["bssid"]
        if own_bssids and seen_bssid in own_bssids:
            # The router's own AP is not a neighbour.
            continue
        for own_ssid in own_ssids:
            rule = classify_lookalike(
                seen_ssid=seen_ssid,
                seen_bssid=seen_bssid,
                own_ssid=own_ssid,
                own_bssids=own_bssids,
            )
            if rule is None:
                continue
            findings.append(
                {
                    "finding": "lookalike_ssid",
                    "rule": rule,
                    "own_ssid": _enveloped(source, own_ssid),
                    "seen_ssid": _enveloped(source, seen_ssid),
                    "channel": result["channel"],
                    "signal": result["signal"],
                }
            )
            break
    findings.sort(key=lambda finding: (-finding["signal"], finding["channel"]))
    return findings[:MAX_FINDINGS]


def summarise(
    *,
    radio: str,
    results: list[dict[str, Any]],
    own_ssids: list[str],
    own_channel: int | None,
    own_bssids: frozenset[str] | set[str],
    source: str,
) -> dict[str, Any]:
    """The summary of one Wi-Fi survey.

    ``results`` are the parsed scan entries (ssid, bssid, channel,
    signal); ``own_ssids`` are the router's own enabled SSIDs; ``own_bssid``
    is the router's own BSSID set (empty when the router reported none).
    """
    own = {mac for mac in own_bssids if mac}
    bands: dict[str, dict[int, list[int]]] = {}
    for result in results:
        band = band_of_channel(result["channel"])
        channels = bands.setdefault(band, {})
        channels.setdefault(result["channel"], []).append(result["signal"])
    band_entries: list[dict[str, Any]] = []
    for band in sorted(bands, key=_band_order):
        channels = bands[band]
        band_entries.append(
            {
                "radio": radio,
                "band": band,
                "networks": sum(len(signals) for signals in channels.values()),
                "channels": [
                    {
                        "channel": channel,
                        "networks": len(channels[channel]),
                        "strongest_dbm": max(channels[channel]),
                    }
                    for channel in sorted(channels)
                ],
            }
        )
    findings: list[dict[str, Any]] = []
    crowded = channel_crowded_finding(
        radio=radio,
        own_channel=own_channel,
        results=results,
        own_bssids=own,
    )
    if crowded is not None:
        findings.append(crowded)
    findings.extend(
        lookalike_findings(
            results=results,
            own_ssids=own_ssids,
            own_bssids=own,
            source=source,
        )
    )
    return {
        "radio": radio,
        "bands": band_entries,
        "findings": findings,
        "networks": len(results),
        "channels": len({result["channel"] for result in results}),
        "same_name_check": (
            SAME_NAME_CHECK_RAN if own else SAME_NAME_CHECK_UNAVAILABLE
        ),
    }


# ---- the router's wireless configuration --------------------------------


def _uci_value(raw: str) -> str:
    """One `uci show` value: unquoted and unescaped."""
    text = raw.strip()
    if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
        text = _UCI_UNESCAPE_RE.sub(r"\1", text[1:-1])
    return text


def _wireless_sections(text: str) -> dict[str, dict[str, str]]:
    """The wireless config as {section: {option: value}}.

    A section's own line (the one without an option) is stored under the
    key ``"type"``.
    """
    sections: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        match = _UCI_LINE_RE.match(line.strip())
        if match is None:
            continue
        section = match.group("section")
        option = match.group("option")
        entry = sections.setdefault(section, {})
        if option is None:
            entry["type"] = _uci_value(match.group("value"))
        else:
            entry[option] = _uci_value(match.group("value"))
    return sections


def _radio_sections(text: str) -> dict[str, dict[str, str]]:
    """The radio sections of the wireless config, by name."""
    return {
        name: options
        for name, options in _wireless_sections(text).items()
        if _RADIO_NAME_RE.fullmatch(name)
    }


def _iface_sections(text: str) -> dict[str, dict[str, str]]:
    """The wireless interface sections of the wireless config."""
    return {
        name: options
        for name, options in _wireless_sections(text).items()
        if _RADIO_NAME_RE.fullmatch(name) is None
        and _IFACE_OPTIONS & set(options)
    }


def _belongs_to_radio(options: dict[str, str], radio: str) -> bool:
    """True when a wireless interface section belongs to the radio.

    A section without a ``device`` option belongs to the radio it is the
    only one of; the router's own configuration always names the device.
    """
    device = options.get("device")
    return device is None or device == radio


def _is_enabled_ap(options: dict[str, str], radio: str) -> bool:
    """True for an enabled access-point interface of the radio."""
    if not _belongs_to_radio(options, radio):
        return False
    if options.get("mode") != "ap":
        return False
    return options.get("disabled", "0").lower() not in _DISABLED_VALUES


def has_radio(text: str, radio: str) -> bool:
    """True when the router's wireless config has the radio section."""
    return radio in _radio_sections(text)


def own_channel(text: str, radio: str) -> int | None:
    """The channel the router's radio is configured for."""
    options = _radio_sections(text).get(radio)
    if not options:
        return None
    raw = options.get("channel", "")
    if not raw.isdigit():
        return None
    channel = int(raw)
    return channel if channel > 0 else None


def own_ssids(text: str, radio: str) -> list[str]:
    """The enabled SSIDs the router broadcasts on the radio."""
    names: list[str] = []
    for options in _iface_sections(text).values():
        if not _is_enabled_ap(options, radio):
            continue
        ssid = options.get("ssid", "")
        if ssid:
            names.append(ssid)
    return names


def up_ap_ifnames(text: str, radio: str) -> list[str]:
    """The interface names of the radio's enabled access points."""
    names: list[str] = []
    for options in _iface_sections(text).values():
        if not _is_enabled_ap(options, radio):
            continue
        ifname = options.get("ifname", "")
        if ifname:
            names.append(ifname)
    return names


def own_bssids_from_uci(text: str, radio: str) -> set[str]:
    """The MAC addresses configured for the scanned radio.

    The radio's ``macaddr`` option and the ``macaddr`` of interface
    sections whose device is that radio are the BSSIDs its access points
    use.  Another radio's addresses do not belong to this scan.
    """
    found: set[str] = set()
    candidates: list[dict[str, str]] = []
    radio_options = _radio_sections(text).get(radio)
    if radio_options is not None:
        candidates.append(radio_options)
    for options in _iface_sections(text).values():
        if options.get("device") == radio:
            candidates.append(options)
    for options in candidates:
        raw = options.get("macaddr")
        if not raw:
            continue
        mac = normalise_mac(raw)
        if mac:
            found.add(mac)
    return found


def normalise_mac(value: str) -> str:
    """The lower-case colon form of a MAC address, or "" when it is not one."""
    cleaned = value.strip().lower().replace("-", ":")
    return cleaned if _MAC_RE.fullmatch(cleaned) else ""


def bssids_from_iwinfo(text: str) -> set[str]:
    """The BSSIDs an ``iwinfo <iface> info`` reply names."""
    found: set[str] = set()
    for match in _IWINFO_BSSID_RE.finditer(text):
        mac = normalise_mac(match.group(1))
        if mac:
            found.add(mac)
    return found
