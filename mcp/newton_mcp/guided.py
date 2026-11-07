"""Guided setup (ROADMAP item 7).

Two interview shapes share one module so the MCP tool keeps one entry
point: the legacy 10-question ``LEGACY_QUESTIONS`` (byte-stable against
``mcp/tests/fixtures/guided_v1_golden.json``) and the v2 14-question
typed ``QUESTIONS`` (design section 3). The control-id
mapping for both lives ONLY in ``profiles/openwrt/intents.toml`` (read
via ``load_intents``); ``AUDIT_ITEMS``, ``control_status`` and
``_find_entry`` keep their v1 behaviour verbatim.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import probes, tiers
from . import envelope as envelope_module
from . import receipts as _receipts
from .adapters.getters import enabled_getters


TIER_NAMES: tuple[str, ...] = ("standard", "hardened", "lockdown")


# Platform id allowlist; reused by recommend, load_intents and confirmation_record.
_PLATFORM_RE = re.compile(r"^[a-z0-9_]{1,32}$")
# Intent id allowlist.
_INTENT_ID_RE = re.compile(r"^INT-[A-Z0-9-]{1,40}$")
# OpenWrt control id an [[intent]] entry may map to: OW-, 2-8 upper-case
# alphanumerics, a dash, then exactly two digits. Absent for audit-only
# intents; when present it must be this and nothing else, so a control id
# can never carry a path, a lower-case or padded form.
_CONTROL_ID_RE = re.compile(r"^OW-[A-Z0-9]{2,8}-[0-9]{2}$")
# Ports: tcp|udp / 1..65535, no leading zeros.
_PORT_RE = re.compile(r"^(tcp|udp)/([1-9][0-9]{0,4})$")
# RFC 1123 hostname: total length <= 253, labels 1-63 chars of [A-Za-z0-9-],
# not starting or ending with "-"; a single trailing dot is rejected too.
_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
# Confirmation file id: lower-case hex sha256.
_CONF_ID_RE = re.compile(r"^[0-9a-f]{64}$")


# ---- KNOWN_INTENTS ---------------------------------------------------------


#: Every vendor-neutral intent id Newton can produce. ``recommend`` will
#: refuse an unknown intent id (so a typo in the platform file fails
#: closed) and the v2 test suite asserts every intent ends up in this set.
KNOWN_INTENTS: tuple[str, ...] = (
    "INT-MGMT-SRC",
    "INT-MGMT-NO-TELNET",
    "INT-MGMT-NO-WEB",
    "INT-MGMT-NO-API",
    "INT-SNMP-V3-ONLY",
    "INT-SNMP-OFF",
    "INT-SSH-KEYS-ONLY",
    "INT-INBOUND-NONE",
    "INT-INBOUND-LIST",
    "INT-UPNP-ON",
    "INT-UPNP-OFF",
    "INT-SEG-GUEST",
    "INT-SEG-IOT",
    "INT-SEG-SERVERS",
    "INT-SEG-MGMT",
    "INT-WIFI-WPA2-COMPAT",
    "INT-WIFI-WPA3-ONLY",
    "INT-DNS-DNSSEC",
    "INT-DNS-ENCRYPTED",
    "INT-V6-OFF",
    "INT-VPN-NONE",
    "INT-VPN-SITE",
    "INT-VPN-ROAD",
    "INT-LOG-REMOTE",
    "INT-NTP-SERVERS",
    "INT-FW-UPDATE-CHECK",
)
_KNOWN_INTENT_SET: frozenset[str] = frozenset(KNOWN_INTENTS)


# ---- GuidedError ----------------------------------------------------------


try:
    from .server import NewtonError as _NewtonError
except Exception:  # pragma: no cover - server import rarely fails
    _NewtonError = Exception


class GuidedError(_NewtonError):
    """A client-safe validation or derivation error.

    Subclasses ``NewtonError`` when the server module imports, so
    the ``call_tool`` wrapper's ``except NewtonError`` turns a guided
    failure into a tool ``{"error": ...}`` result. The message names
    the offending key and never echoes the rejected value.
    """


def _raise(message: str) -> None:
    raise GuidedError(message)


# ---- LEGACY_QUESTIONS (v1 10-question interview) --------------------------


# v1 interview keeps its question texts so the byte-stable legacy
# report (golden fixture) keeps the same owner_reason strings. The
# control-id mapping lives only in ``intents.toml``:
# ``_LEGACY_INTENT_MAP`` -> intent id -> ``load_intents`` ->
# (control_id, tier, form_of).
LEGACY_QUESTIONS: list[dict[str, Any]] = [
    {"id": "strictness",       "text": "How strict should this router be: normal home use, stricter even if some convenience breaks, or maximum restriction?",
     "answers": ("normal", "stricter", "maximum")},
    {"id": "wifi_wpa2",        "text": "Do any Wi-Fi devices need WPA2, or are you unsure?",
     "answers": ("yes", "unsure", "all_wpa3")},
    {"id": "guest_network",    "text": "Do you want a separate guest network that cannot reach your main devices?",
     "answers": ("yes", "no")},
    {"id": "upnp",             "text": "Do games or consoles need UPnP/NAT-PMP to open ports automatically?",
     "answers": ("yes", "no")},
    {"id": "iot_network",      "text": "Do you want an isolated IoT network, accepting that casting/discovery may need extra rules?",
     "answers": ("yes", "no")},
    {"id": "ssh_password_off", "text": "After a separate key login is proven, do you want password SSH disabled?",
     "answers": ("yes", "no")},
    {"id": "dnssec",           "text": "Do you want DNSSEC validation, with a correct clock and dnsmasq-full installed?",
     "answers": ("yes", "no")},
    {"id": "encrypted_dns",    "text": "Do you want encrypted upstream DNS despite captive-portal/bootstrap risk?",
     "answers": ("yes", "no")},
    {"id": "ipv6_off",         "text": "Do you deliberately want IPv6 disabled everywhere?",
     "answers": ("yes", "no", "unsure")},
    {"id": "fw_update_check",  "text": "Do you want a read-only firmware-update availability check?",
     "answers": ("yes", "no")},
]

_LEGACY_BY_ID: dict[str, dict[str, Any]] = {q["id"]: q for q in LEGACY_QUESTIONS}
LEGACY_STRICTNESS_TIER = {"normal": "standard", "stricter": "hardened", "maximum": "lockdown"}

# ---- AUDIT_ITEMS ---------------------------------------------------------

AUDIT_ITEMS: tuple[dict[str, Any], ...] = (
    {"id": "listeners",     "title": "Listeners",    "commands": ["netstat -tulpn"]},
    {"id": "services",      "title": "Services",     "commands": ["apk list -I", "netstat -tulpn"]},
    {"id": "port_forwards", "title": "Port forwards",
     "commands": ["uci show firewall", "nft list ruleset"]},
    {"id": "upnp",          "title": "UPnP",
     "commands": ["uci show upnpd", "apk list -I miniupnpd-nftables", "netstat -tulpn"]},
    {"id": "wifi",          "title": "Wi-Fi settings",
     "commands": ["uci show wireless", "ubus call network.wireless status", "wifi status", "iwinfo"]},
    {"id": "dhcp",          "title": "DHCP devices",
     "commands": ["cat /tmp/dhcp.leases", "uci show dhcp"]},
)

_AUDIT_IDS: frozenset[str] = frozenset(item["id"] for item in AUDIT_ITEMS)

# Vendor-neutral v2 interview. Aliases from v1 ids are folded
# in ``normalize``; the mapping from answered question -> intent id lives
# only in ``profiles/<platform>/intents.toml`` and is read by
# ``load_intents``.
_V2_QUES: list[dict[str, Any]] = [
    {"id": "device_kind",      "text": "What kind of device is this?",
     "type": "enum",      "answers": ("home_router", "office_firewall", "switch", "edge_router", "not_sure"),
     "max": None, "applies_to": ""},
    {"id": "strictness",       "text": "How strict should this router be: normal home use, stricter even if some convenience breaks, or maximum restriction?",
     "type": "enum",      "answers": ("normal", "stricter", "maximum"),
     "max": None, "applies_to": ""},
    {"id": "admin_source",     "text": "Where may admins log in from? Anywhere opens the router to the whole internet; choose carefully.",
     "type": "enum",      "answers": ("lan_only", "mgmt_network", "vpn_only", "anywhere"),
     "max": None, "applies_to": ""},
    {"id": "admin_access",     "text": "Which admin ways stay on? Telnet and SNMPv1/v2 send credentials in cleartext; consider turning them off.",
     "type": "multi_enum","answers": ("ssh", "web_ui", "api", "telnet", "snmp_v3", "snmp_v1v2"),
     "max": None, "applies_to": ""},
    {"id": "ssh_password_off", "text": "After a separate key login is proven, do you want password SSH disabled?",
     "type": "enum",      "answers": ("yes", "no"),
     "max": None, "applies_to": ""},
    {"id": "inbound_services", "text": "Which services may reach in from the internet?",
     "type": "port_list", "answers": (), "max": 32, "applies_to": ""},
    {"id": "upnp",             "text": "Do games or consoles need UPnP/NAT-PMP to open ports automatically?",
     "type": "enum",      "answers": ("yes", "no"),
     "max": None, "applies_to": "home router"},
    {"id": "segments",         "text": "Which separate segments should the network have?",
     "type": "multi_enum","answers": ("guest", "iot", "servers", "management"),
     "max": None, "applies_to": ""},
    {"id": "wifi_wpa2",        "text": "Do any Wi-Fi devices need WPA2, or are you unsure?",
     "type": "enum",      "answers": ("yes", "unsure", "all_wpa3"),
     "max": None, "applies_to": "Wi-Fi devices"},
    {"id": "dns",              "text": "DNSSEC validation? Encrypted upstream DNS?",
     "type": "multi_enum","answers": ("dnssec", "encrypted"),
     "max": None, "applies_to": ""},
    {"id": "ipv6_off",         "text": "Do you deliberately want IPv6 disabled everywhere?",
     "type": "enum",      "answers": ("yes", "no", "unsure"),
     "max": None, "applies_to": ""},
    {"id": "remote_vpn",       "text": "Which remote-access VPN is in use?",
     "type": "enum",      "answers": ("none", "site_to_site", "road_warrior"),
     "max": None, "applies_to": ""},
    {"id": "log_time_hosts",   "text": "Where do syslog and NTP go?",
     "type": "host_lists","answers": (), "max": 4, "applies_to": ""},
    {"id": "fw_update_check",  "text": "Do you want a read-only firmware-update availability check?",
     "type": "enum",      "answers": ("yes", "no"),
     "max": None, "applies_to": ""},
]

#: The 14 v2 interview questions in spec order, with the six contract
#: keys ``(id, text, type, answers, max, applies_to)``. Legacy v1 ids
#: are accepted only through ``normalize``.
QUESTIONS: list[dict[str, Any]] = list(_V2_QUES)

_V2_BY_ID: dict[str, dict[str, Any]] = {q["id"]: q for q in QUESTIONS}


# Aliases: old v1 ids that became v2 composites; the validator folds
# alias ids into the canonical question's answer.
_ALIAS_TO_CANONICAL: dict[str, str] = {
    "guest_network": "segments",
    "iot_network": "segments",
    "dnssec": "dns",
    "encrypted_dns": "dns",
}


# ---- public surface helpers ------------------------------------------------


def questions() -> list[dict[str, Any]]:
    """Return the v2 interview as ``[{id, text, type, answers, max, applies_to}, ...]``."""
    return [
        {
            "id": q["id"],
            "text": q["text"],
            "type": q["type"],
            "answers": tuple(q["answers"]),
            "max": q["max"],
            "applies_to": q["applies_to"],
        }
        for q in QUESTIONS
    ]


# ---- legacy detection / normalisation -------------------------------------


_LEGACY_IDS: frozenset[str] = frozenset(q["id"] for q in LEGACY_QUESTIONS)


def _is_legacy_input(answers: Any) -> bool:
    """A v1 dict has only legacy ids and string values."""
    if not isinstance(answers, dict) or not answers:
        return False
    return all(k in _LEGACY_IDS and isinstance(v, str) for k, v in answers.items())


# ---- validators ------------------------------------------------------------


def _ensure_list(qid: str, value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    _raise(f"answer for {qid} is not a list (the rejected value is not echoed)")


def _bad_port(port: str) -> str:
    """Validate a port token without echoing the rejected value.
    Returns ``""`` on success."""
    if not isinstance(port, str):
        return "value is not a string"
    m = _PORT_RE.fullmatch(port)
    if m is None or not 1 <= int(m.group(2)) <= 65535:
        return "value does not match tcp|udp/N with N in 1..65535"
    return ""


def _bad_host(host: Any) -> str:
    """Validate a host (IPv4, IPv6 or RFC 1123 hostname); the rejected
    value is never echoed. Returns ``""`` on success."""
    if not isinstance(host, str):
        return "value is not a string"
    if not host:
        return "value is empty"
    # IP literal first. Reject zone ids ("fe80::1%eth0") and brackets
    # so the untrusted envelope cannot anchor a parse on an interface.
    if "%" in host or "[" in host or "]" in host:
        return "value is not a valid IP literal or RFC 1123 hostname"
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    # RFC 1123 hostname.
    if len(host) > 253 or host.endswith("."):
        return "value is not a valid RFC 1123 hostname"
    for label in host.split("."):
        if not _HOSTNAME_LABEL_RE.fullmatch(label):
            return "value is not a valid RFC 1123 hostname"
    return ""


# ---- normalize -------------------------------------------------------------


def normalize(answers: Any) -> dict[str, Any]:
    """Validate and fold a v2 (or v2-with-aliases) answer dict.

    Returns canonical v2 answers keyed by v2 id. Raises
    ``GuidedError`` for every failure mode; the message names the
    question id and never echoes the rejected value. ``strictness``
    is required.

    Legacy v1 dicts are accepted: each legacy alias folds into the
    matching v2 composite (``segments`` / ``dns``).
    """
    if not isinstance(answers, dict):
        _raise("answers must be a dict of question id -> answer value")
    if "strictness" not in answers:
        _raise("strictness is required")

    # Fold alias ids first so an alias + canonical id is caught in
    # either input order.
    alias_given: dict[str, dict[str, str]] = {}
    for qid in answers:
        if qid in _ALIAS_TO_CANONICAL:
            canon = _ALIAS_TO_CANONICAL[qid]
            alias_given.setdefault(canon, {})[qid] = answers[qid]

    canonical: dict[str, Any] = {}
    for qid, raw in answers.items():
        if qid in _ALIAS_TO_CANONICAL:
            continue
        if qid not in _V2_BY_ID:
            _raise(
                "unknown question id (the rejected id is not echoed); "
                f"known ids: {', '.join(q['id'] for q in QUESTIONS)}"
            )
        q = _V2_BY_ID[qid]
        if qid in alias_given:
            _raise(
                f"question {qid} was answered both as a v2 id and as a "
                "v1 alias; pick one form"
            )
        canonical[qid] = _validate_one(qid, raw, q)

    for canon_qid, alias_answers in alias_given.items():
        if canon_qid in canonical:
            _raise(
                f"question {canon_qid} was answered both as a v2 id "
                "and as a v1 alias; pick one form"
            )
        existing: Any = None
        q = _V2_BY_ID[canon_qid]
        for alias_id, raw in alias_answers.items():
            existing = _fold_alias_specific(
                canon_qid, alias_id, raw, existing
            )
        canonical[canon_qid] = existing

    if "strictness" not in canonical:
        _raise("strictness answer did not validate")
    return canonical


def _fold_alias_specific(canon_qid: str, alias_id: str, raw: Any,
                         existing: Any) -> Any:
    """Folding helper for canonical questions with multiple aliases.

    ``existing`` is the already-folded canonical answer (a list for
    multi_enum) or ``None``.
    """
    if canon_qid == "segments":
        token_map = {"guest_network": "guest", "iot_network": "iot"}
    elif canon_qid == "dns":
        token_map = {"dnssec": "dnssec", "encrypted_dns": "encrypted"}
    else:
        _raise(f"answer for {canon_qid} failed validation")
    token = token_map.get(alias_id)
    if token is None:
        _raise(f"answer for {canon_qid} failed validation")
    if not isinstance(raw, str) or raw not in ("yes", "no"):
        _raise(f"answer for {canon_qid} failed validation")
    base_list = list(existing) if isinstance(existing, list) else []
    if raw == "yes" and token not in base_list:
        base_list.append(token)
    elif raw == "no" and token in base_list:
        base_list.remove(token)
    if canon_qid in _V2_BY_ID:
        allowed = _V2_BY_ID[canon_qid]["answers"]
        if any(item not in allowed for item in base_list):
            _raise(f"answer for {canon_qid} failed validation")
        return [a for a in allowed if a in base_list]
    return base_list


def _validate_enum(qid: str, raw: Any, q: dict[str, Any]) -> Any:
    if not isinstance(raw, str):
        _raise(f"answer for {qid} is not a string "
               "(the rejected value is not echoed)")
    if raw not in q["answers"]:
        _raise(f"answer for {qid} is not one of the allowed values; "
               f"allowed: {', '.join(q['answers'])}")
    return raw


def _validate_multi_enum(qid: str, raw: Any, q: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    for item in _ensure_list(qid, raw):
        if not isinstance(item, str):
            _raise(f"answer for {qid} contains a non-string item")
        if item in seen:
            _raise(f"answer for {qid} contains a duplicate item")
        if item not in q["answers"]:
            _raise(f"answer for {qid} contains an item not in the "
                   f"allowed set; allowed: {', '.join(q['answers'])}")
        seen.add(item)
    return [a for a in q["answers"] if a in seen]


def _validate_port_list(qid: str, raw: Any, q: dict[str, Any]) -> list[str]:
    items = _ensure_list(qid, raw)
    if len(items) > q["max"]:
        _raise(f"answer for {qid} has too many items; max is {q['max']}")
    parsed: list[tuple[str, int]] = []
    seen_keys: set[tuple[str, int]] = set()
    for item in items:
        if isinstance(item, str) and not _bad_port(item):
            proto, num = item.split("/")
            key = (proto, int(num))
        else:
            _raise(f"answer for {qid} contains an invalid port")
        if key in seen_keys:
            _raise(f"answer for {qid} contains a duplicate port")
        seen_keys.add(key)
        parsed.append(key)
    parsed.sort(key=lambda p: (p[0], p[1]))
    return [f"{p[0]}/{p[1]}" for p in parsed]


def _validate_host_lists(qid: str, raw: Any, q: dict[str, Any]) -> dict[str, list[str]]:
    if not isinstance(raw, dict):
        _raise(f"answer for {qid} is not a dict")
    if set(raw.keys()) - {"syslog", "ntp"}:
        _raise(f"answer for {qid} has an unknown key "
               "(the rejected key is not echoed)")
    out: dict[str, list[str]] = {"syslog": [], "ntp": []}
    for sub in ("syslog", "ntp"):
        if sub not in raw:
            continue
        items = _ensure_list(qid, raw[sub])
        if len(items) > q["max"]:
            _raise(f"answer for {qid} ({sub}) has too many items; "
                   f"max is {q['max']}")
        seen_local: set[str] = set()
        cleaned: list[str] = []
        for item in items:
            if _bad_host(item):
                _raise(f"answer for {qid} contains an invalid host")
            if item in seen_local:
                _raise(f"answer for {qid} contains a duplicate host")
            seen_local.add(item)
            cleaned.append(item)
        out[sub] = cleaned
    return out


_VALIDATORS = {
    "enum": _validate_enum, "multi_enum": _validate_multi_enum,
    "port_list": _validate_port_list, "host_lists": _validate_host_lists,
}


def _validate_one(qid: str, raw: Any, q: dict[str, Any]) -> Any:
    """Validate one v2 answer; return canonical value or raise
    ``GuidedError``. The message names the question id and never
    echoes the rejected value."""
    fn = _VALIDATORS.get(q["type"])
    if fn is None:
        _raise(f"answer for {qid} has an unknown question type")
    return fn(qid, raw, q)


# ---- intent resolution ----------------------------------------------------


_LEGACY_INTENT_MAP: dict[tuple[str, str], str] = {
    ("wifi_wpa2", "yes"): "INT-WIFI-WPA2-COMPAT",
    ("wifi_wpa2", "unsure"): "INT-WIFI-WPA2-COMPAT",
    ("wifi_wpa2", "all_wpa3"): "INT-WIFI-WPA3-ONLY",
    ("guest_network", "yes"): "INT-SEG-GUEST",
    ("upnp", "yes"): "INT-UPNP-ON",
    ("upnp", "no"): "INT-UPNP-OFF",
    ("iot_network", "yes"): "INT-SEG-IOT",
    ("ssh_password_off", "yes"): "INT-SSH-KEYS-ONLY",
    ("dnssec", "yes"): "INT-DNS-DNSSEC",
    ("encrypted_dns", "yes"): "INT-DNS-ENCRYPTED",
    ("ipv6_off", "yes"): "INT-V6-OFF",
    ("fw_update_check", "yes"): "INT-FW-UPDATE-CHECK",
}


def _intents_admin_access(value: Any) -> list[str]:
    items = set(value or [])
    out: list[str] = []
    if "telnet" not in items:
        out.append("INT-MGMT-NO-TELNET")
    if "snmp_v3" in items and "snmp_v1v2" not in items:
        out.append("INT-SNMP-V3-ONLY")
    elif "snmp_v3" not in items and "snmp_v1v2" not in items:
        out.append("INT-SNMP-OFF")
    if "web_ui" not in items:
        out.append("INT-MGMT-NO-WEB")
    if "api" not in items:
        out.append("INT-MGMT-NO-API")
    return out


def _intents_segments(value: Any) -> list[str]:
    items = set(value or [])
    out: list[str] = []
    for token, intent in (
        ("guest", "INT-SEG-GUEST"), ("iot", "INT-SEG-IOT"),
        ("servers", "INT-SEG-SERVERS"), ("management", "INT-SEG-MGMT"),
    ):
        if token in items:
            out.append(intent)
    return out


def _intents_wifi_wpa2(value: Any) -> list[str]:
    if value in ("yes", "unsure"):
        return ["INT-WIFI-WPA2-COMPAT"]
    if value == "all_wpa3":
        return ["INT-WIFI-WPA3-ONLY"]
    return []


def _intents_dns(value: Any) -> list[str]:
    items = set(value or [])
    out: list[str] = []
    for token, intent in (("dnssec", "INT-DNS-DNSSEC"), ("encrypted", "INT-DNS-ENCRYPTED")):
        if token in items:
            out.append(intent)
    return out


def _intents_remote_vpn(value: Any) -> list[str]:
    return {
        "none": ["INT-VPN-NONE"], "site_to_site": ["INT-VPN-SITE"],
        "road_warrior": ["INT-VPN-ROAD"],
    }.get(value or "", [])


def _intents_log_time_hosts(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        if value.get("syslog"):
            out.append("INT-LOG-REMOTE")
        if value.get("ntp"):
            out.append("INT-NTP-SERVERS")
    return out


_V2_INTENTS_FOR_QUESTION: dict[str, Any] = {
    "device_kind":      lambda _v: [],
    "admin_source":     lambda _v: ["INT-MGMT-SRC"],
    "admin_access":     _intents_admin_access,
    "ssh_password_off": lambda v: ["INT-SSH-KEYS-ONLY"] if v == "yes" else [],
    "inbound_services": lambda v: ["INT-INBOUND-NONE"] if not v else ["INT-INBOUND-LIST"],
    "upnp":             lambda v: ["INT-UPNP-ON"] if v == "yes" else ["INT-UPNP-OFF"],
    "segments":         _intents_segments,
    "wifi_wpa2":        _intents_wifi_wpa2,
    "dns":              _intents_dns,
    "ipv6_off":         lambda v: ["INT-V6-OFF"] if v == "yes" else [],
    "remote_vpn":       _intents_remote_vpn,
    "log_time_hosts":   _intents_log_time_hosts,
    "fw_update_check":  lambda v: ["INT-FW-UPDATE-CHECK"] if v == "yes" else [],
}


# ---- shared helpers --------------------------------------------------------


def _load_all_controls(controls=None) -> list[dict[str, Any]]:
    """Return controls (or load from the manifest override)."""
    return controls if controls is not None else probes._load_controls(probes.manifest_path())


def _find_entry(control_id: str, tier: str | None, form_of: str,
                controls: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick one manifest entry for an id shared between forms.

    Match ``tier`` and (if given) ``form_of``; otherwise fall back
    to the base entry (``form_of == ''`` and ``step_up_of == ''``);
    otherwise the first match.
    """
    matches = [c for c in controls if c.get("id") == control_id]
    if not matches:
        return None
    if tier is not None:
        pick = [c for c in matches if c.get("tier") == tier]
        if form_of:
            sub = [c for c in pick if c.get("form_of") == form_of]
            if sub:
                return sub[0]
        if pick:
            return pick[0]
    base = [c for c in matches
            if not c.get("step_up_of")
            and not c.get("form_of")]
    if base:
        return base[0]
    return matches[0]


def _tier_skipped_map(directory: Path) -> dict[str, dict[str, str]]:
    """Return ``{control_id: {"reason": ..., "tier": ...}}`` for
    every control the three tier files mark skipped."""
    out: dict[str, dict[str, str]] = {}
    for tier in TIER_NAMES:
        info = tiers.split_tier(tier, directory=directory)
        for s in info["skipped"]:
            out[s["id"]] = {"reason": s["reason"], "tier": tier}
    return out


_CONFIDENCE_FOR_STATUS = {
    "plan-ready": "high",
    "audit-only": "medium",
    "skipped":    "low",
    "gap":        "low",
}


def _build_recommendation_dict(
    *, control_id: str, tier_selector: str | None, form_of: str,
    report_tier: str, owner_reason: str,
    controls: list[dict[str, Any]], directory: Path,
) -> dict[str, Any]:
    """Build one ``guided_setup_report`` recommendation dict, shared by
    legacy and v2 paths so they cannot drift.

    ``tier_selector`` is the intent's tier (``opt-in`` included;
    ``None`` means "pick the base entry"). ``form_of`` selects an
    alternative form (``""`` means base). ``owner_reason`` is
    supplied by the caller so the two paths keep distinct texts.
    """
    entry = _find_entry(control_id, tier_selector, form_of, controls)
    if entry is None:
        status = {"status": "gap", "reason": "not in manifest"}
        preconditions: list[str] = []
        notes = ""
    else:
        status = control_status(
            control_id, controls=controls, directory=directory,
            tier=tier_selector, form_of=form_of,
        )
        preconditions = [str(p) for p in (entry.get("preconditions") or [])]
        notes = str(entry.get("notes") or "")

    desired_state = report_tier
    if entry is not None:
        if entry.get("form_of"):
            desired_state = (
                f"{report_tier} opt-in form (UPnP on)"
                if control_id == "OW-FW-06" else f"{report_tier} form"
            )
        elif entry.get("tier") == "opt-in":
            desired_state = f"{report_tier} opt-in"
    benefit = str(entry.get("title", "")) if entry is not None else control_id
    return {
        "control_id": control_id, "current_state": "not audited",
        "desired_state": desired_state, "owner_reason": owner_reason,
        "evidence": [], "benefit": benefit,
        "breakage_or_preconditions": (
            "; ".join(preconditions) if preconditions else (notes or "")
        ),
        "confidence": _CONFIDENCE_FOR_STATUS.get(status["status"], "low"),
        "status": status["status"],
    }


# ---- public API: control_status (unchanged v1 behaviour) ------------------


def control_status(
    control_id: str, *,
    controls: list[dict[str, Any]] | None = None,
    directory: Path | None = None,
    tier: str | None = None, form_of: str = "",
) -> dict[str, str]:
    """Derive ``{"status", "reason"}`` for one manifest control id.

    Resolution order: missing id, ``lab == "not-yet"``, lab-bound
    batch, ``lab == "audit"``, tier-file skipped, empty batch,
    ``"plan-ready"``. ``tier``/``form_of`` select between entries
    sharing an id; the base entry wins when neither is given.
    """
    if directory is None:
        directory = Path(probes.manifest_path()).parent
    entry = _find_entry(
        control_id, tier=tier, form_of=form_of,
        controls=_load_all_controls(controls),
    )
    if entry is None:
        return {"status": "gap", "reason": "not in manifest"}

    lab = entry.get("lab", "")
    lab_bound = entry.get("lab_bound") or []
    if isinstance(lab_bound, list) and "batch" in lab_bound:
        return {"status": "gap", "reason": "current batch is nonportable"}
    if lab == "not-yet":
        return {"status": "gap", "reason": "not-yet"}
    if lab == "audit":
        return {"status": "audit-only",
                "reason": "manifest marks this control audit-only"}

    # Only the chosen entry's own tier-file status applies. opt-in
    # and 'none' entries never appear in a tier file, so the tier
    # file's status for a same-id base entry must not leak in.
    if entry.get("tier") in TIER_NAMES:
        skipped = _tier_skipped_map(directory)
        if control_id in skipped:
            return {"status": "skipped", "reason": skipped[control_id]["reason"]}

    batch = entry.get("batch")
    if not isinstance(batch, list) or len(batch) == 0:
        return {"status": "gap", "reason": "no active lines in manifest"}
    return {"status": "plan-ready", "reason": "plan-ready"}


# ---- legacy recommend() (byte-stable) ------------------------------------


def _legacy_tier(legacy: dict[str, str]) -> str:
    strictness = legacy.get("strictness")
    if strictness not in LEGACY_STRICTNESS_TIER:
        _raise(
            "answer for strictness is not one of the allowed values; "
            f"allowed: {', '.join(LEGACY_STRICTNESS_TIER)}"
        )
    return LEGACY_STRICTNESS_TIER[strictness]


def _legacy_validate(answers: dict[str, str]) -> dict[str, str]:
    if not isinstance(answers, dict):
        _raise("answers must be a dict of question id -> answer value")
    if "strictness" not in answers:
        _raise("strictness is required")

    validated: dict[str, str] = {}
    for qid, raw in answers.items():
        q = _LEGACY_BY_ID.get(qid)
        if q is None:
            _raise(
                "unknown question id (the rejected id is not echoed); "
                f"known ids: {', '.join(_LEGACY_BY_ID)}"
            )
        if not isinstance(raw, str):
            _raise(
                f"answer for {qid} is not a string (the rejected value "
                "is not echoed)"
            )
        if raw not in q["answers"]:
            _raise(
                f"answer for {qid} is not one of the allowed values; "
                f"allowed: {', '.join(q['answers'])}"
            )
        validated[qid] = raw
    return validated


_SCANS_NOT_RUN = ("nmap_inside", "nmap_outside", "wifi_scan", "kismet")
_APPROVAL_NOTE = (
    "recommendations only; each plan needs its own out-of-band "
    "owner approval"
)


def _empty_v1_report_skeleton(tier: str) -> dict[str, list[Any] | str]:
    return {
        "report": "guided_setup_report", "tier": tier,
        "answers": [], "audit_run": [], "scans_run": [],
        "scans_not_run": list(_SCANS_NOT_RUN),
        "findings": [], "recommendations": [], "unanswered": [],
        "approval": _APPROVAL_NOTE,
    }


def with_scan_result(
    report: dict[str, Any], kind: str, findings: list[dict[str, Any]]
) -> dict[str, Any]:
    """Return a report copy recording one scan that actually completed.

    Planning and consent do not call this helper.  Consequently the two nmap
    entries leave ``scans_not_run`` only after execution produced a result;
    the Wi-Fi survey (``wifi_scan``) and kismet remain honest gaps until
    they run.

    A Wi-Fi finding carries the neighbour's network name, so its SSIDs are
    wrapped in the untrusted envelope here as well: the report is what the
    owner reads, and a name in it must never read as a Newton field.
    """
    if kind not in {"inside", "outside", "wifi"}:
        raise GuidedError("scan kind must be inside, outside or wifi")
    if not isinstance(report, dict) or report.get("report") != "guided_setup_report":
        raise GuidedError("scan result needs a guided_setup_report")
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise GuidedError("scan findings must be a list of objects")
    result = copy.deepcopy(report)
    scan_name = "wifi_scan" if kind == "wifi" else f"nmap_{kind}"
    scans_run = result.get("scans_run")
    scans_not_run = result.get("scans_not_run")
    report_findings = result.get("findings")
    if not isinstance(scans_run, list) or not isinstance(scans_not_run, list) or not isinstance(report_findings, list):
        raise GuidedError("guided setup report has invalid scan fields")
    if scan_name not in scans_run:
        scans_run.append(scan_name)
    result["scans_not_run"] = [name for name in scans_not_run if name != scan_name]
    if kind == "wifi":
        report_findings.extend(_wifi_finding(finding) for finding in findings)
    else:
        report_findings.extend(copy.deepcopy(findings))
    return result


# The source of an SSID the guided report envelopes itself.  The report has
# no device of its own, so the source names the scan.
_WIFI_FINDING_SOURCE = "guided:wifi-scan"


def _wifi_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """One Wi-Fi finding with every SSID inside the untrusted envelope."""
    wrapped = copy.deepcopy(finding)
    for key in ("own_ssid", "seen_ssid"):
        value = wrapped.get(key)
        if value is None:
            continue
        if isinstance(value, dict):
            if not envelope_module.is_envelope(value):
                raise GuidedError(f"wifi finding {key} must be an untrusted envelope")
            continue
        if not isinstance(value, str):
            raise GuidedError(f"wifi finding {key} must be a string or an envelope")
        wrapped[key] = envelope_module.envelope(
            _WIFI_FINDING_SOURCE, envelope_module.escape_delimiters(value)
        )
    return wrapped


def _legacy_recommend(
    answers: dict[str, str], *,
    controls: list[dict[str, Any]] | None = None,
    directory: Path | None = None,
) -> dict[str, Any]:
    """v1 ``guided_setup_report`` builder, byte-stable against the
    golden fixture.

    The control-id mapping lives only in ``intents.toml``:
    ``_LEGACY_INTENT_MAP`` maps (question, answer) -> intent id,
    then ``load_intents`` resolves it -> (control_id, tier, form_of).
    """
    validated = _legacy_validate(answers)
    tier = _legacy_tier(validated)
    all_controls = _load_all_controls(controls)
    if directory is None:
        directory = Path(probes.manifest_path()).parent
    intents_map = load_intents(platform="openwrt", directory=directory)

    recommendations: list[dict[str, Any]] = []
    for q in LEGACY_QUESTIONS:
        qid = q["id"]
        if qid == "strictness" or qid not in validated:
            continue
        entry = intents_map.get(_LEGACY_INTENT_MAP.get((qid, validated[qid])) or "")
        if entry is None or not entry.get("control_id"):
            continue
        recommendations.append(_build_recommendation_dict(
            control_id=entry["control_id"],
            tier_selector=entry.get("tier") or None,
            form_of=entry.get("form_of") or "",
            report_tier=tier,
            owner_reason=f"{q['text']} (answer: {validated[qid]})",
            controls=all_controls, directory=directory,
        ))

    report = _empty_v1_report_skeleton(tier)
    for q in LEGACY_QUESTIONS:
        qid = q["id"]
        if qid in validated:
            report["answers"].append({"id": qid, "answer": validated[qid]})
        else:
            report["unanswered"].append(qid)
    report["unanswered"].sort()
    report["recommendations"] = recommendations
    return report


# ---- intents.toml loader --------------------------------------------------


# OpenWrt-only keys (control_id / tier / form_of) live in
# ``_INTENTS_OPENWRT_EXTRA``; non-OpenWrt platforms never accept them.
# The four service-off-only keys (``check``, ``good``, ``snippet``,
# ``confirm``) are non-OpenWrt only; the global set is the union of
# the two, and each platform subtracts what it does not take.
_INTENTS_OPENWRT_EXTRA = frozenset({"control_id", "tier", "form_of"})
_INTENTS_VENDOR_EXTRA = frozenset({"check", "good", "snippet", "confirm"})
_INTENTS_ALLOWED_KEYS = (
    frozenset({
        "id", "explanation", "doc", "ledger", "audit",
    })
    | _INTENTS_OPENWRT_EXTRA | _INTENTS_VENDOR_EXTRA
)
_SCALAR_KEYS = ("explanation", "doc", "ledger")
# Only the four service-off intents may carry a snippet / confirm pair;
# this is design 8.3 + design 3.4 (decision 9).
_SERVICE_OFF_INTENTS: frozenset[str] = frozenset({
    "INT-MGMT-NO-TELNET",
    "INT-MGMT-NO-WEB",
    "INT-MGMT-NO-API",
    "INT-SNMP-OFF",
})
# Snippet bodies and their enclosing wrappers (UNVERIFIED until
# a lab run); keys are platform ids. ``"<BODY>"`` marks the spot
# where the body lines go; the loader enforces that the wrapper lines
# (everything before and after ``<BODY>``) appear verbatim.
_SNIPPET_WRAPPERS: dict[str, tuple[str, ...]] = {
    "junos": (
        "configure",
        "<BODY>",
        "commit confirmed 10",
    ),
    "eos": (
        "configure session newton-<short>",
        "<BODY>",
        "commit timer 00:10:00",
    ),
    "iosxe": (
        "configure terminal revert timer 10",
        "<BODY>",
        "end",
    ),
    "vyos": (
        "configure",
        "<BODY>",
        "commit-confirm 10",
        "exit",
    ),
    "fortios": (
        "config system global",
        "set cfg-save revert",
        "set cfg-revert-timeout 600",
        "end",
        "<BODY>",
    ),
    "routeros": (
        "# press Ctrl-X to enter Safe Mode before pasting",
        "<BODY>",
    ),
}
# Banned tokens inside any snippet body (case-insensitive, whole word);
# mirrors the prompt's ban list. ``ip`` alone is allowed; only
# ``ipsec`` matches.
_SNIPPET_BANNED_WORDS_RE = re.compile(
    r"(?<![A-Za-z0-9])("
    r"user|username|password|secret|key|keys|authentication|"
    r"privilege|role|community|permit|allow|allowaccess|accept|"
    r"forward|nat|vip|vpn|ipsec|tunnel|wireguard|trusthost|"
    r"address|source|interface|route"
    r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_SNIPPET_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Compressed form (``fe80::1``) or fully specified 8-group form
# (``fe80:0:0:0:0:0:0:1``). A lone ``00:10:00`` (4 hex-ish groups but
# no ``::`` and only 7 separators short of a full address) must NOT
# match -- ``commit timer 00:10:00`` is a legit timer, not an IPv6.
_SNIPPET_IPV6_RE = re.compile(
    r"\b"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F:]+\b"
    r"|::[0-9a-fA-F:]+\b"
    r"|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}\b"
)
_SNIPPET_ANGLE_RE = re.compile(r"<[^>\n]+>")


def _resolve_intents_path(platform: str, directory: Path) -> Path | None:
    if platform == "openwrt":
        path = directory / "intents.toml"
        if not path.exists():
            _raise("intents.toml not found for openwrt")
        return path
    path = directory.parent / platform / "intents.toml"
    return path if path.exists() else None


def load_intents(platform: str = "openwrt",
                 directory: Path | None = None) -> dict[str, dict[str, Any]]:
    """Read ``<directory>/intents.toml`` (openwrt) or
    ``<directory>/../<platform>/intents.toml`` (other).

    Returns intent id -> entry. A missing file for a non-openwrt
    platform returns ``{}``. Refuses duplicate ids, unknown keys,
    audit items outside ``AUDIT_ITEMS``, and ``control_id`` /
    ``tier`` / ``form_of`` on a non-openwrt platform.
    """
    if not _PLATFORM_RE.fullmatch(platform):
        _raise("platform id has an invalid shape")
    if directory is None:
        directory = Path(probes.manifest_path()).parent

    path = _resolve_intents_path(platform, directory)
    if path is None:
        return {}

    with path.open("rb") as fh:
        data = tomllib.load(fh)
    if isinstance(data, dict) and isinstance(data.get("intent"), dict):
        _raise("intents.toml top level must be [[intent]] tables")
    tables = data.get("intent") if isinstance(data, dict) else None
    if not isinstance(tables, list):
        _raise("intents.toml must be a list of [[intent]] tables")

    if platform == "openwrt":
        allowed_keys = _INTENTS_ALLOWED_KEYS - _INTENTS_VENDOR_EXTRA
    else:
        allowed_keys = _INTENTS_ALLOWED_KEYS - _INTENTS_OPENWRT_EXTRA

    out: dict[str, dict[str, Any]] = {}
    for entry in tables:
        _validate_intent_entry(entry, allowed_keys, platform, out)
        out[entry["id"]] = entry
    return out


def _validate_intent_entry(entry: Any, allowed_keys: Any, platform: str,
                            out: dict[str, Any]) -> None:
    """Type-check and key-check one ``[[intent]]`` entry.

    OpenWrt entries only accept ``control_id`` / ``tier`` / ``form_of``;
    other platforms only accept ``check`` / ``good`` / ``snippet`` /
    ``confirm``. Each platform subtracts its denied set from the union
    ``_INTENTS_ALLOWED_KEYS`` so the same loader can pin both shapes.
    An OpenWrt ``control_id`` that is present must fullmatch
    ``_CONTROL_ID_RE`` (absent is fine: audit-only intents map to no
    control).
    """
    if not isinstance(entry, dict):
        _raise("intents.toml has a non-dict [[intent]] entry")
    if set(entry) - allowed_keys:
        _raise("intents.toml has an unknown key on an [[intent]] entry")
    intent_id = entry.get("id")
    if not isinstance(intent_id, str) or not _INTENT_ID_RE.fullmatch(intent_id):
        _raise("intents.toml entry id has an invalid shape")
    if intent_id not in _KNOWN_INTENT_SET:
        _raise("intents.toml entry id is not a known intent id")
    if intent_id in out:
        _raise("intents.toml has a duplicate intent id")
    audit = entry.get("audit", [])
    if (not isinstance(audit, list)
            or any(not isinstance(x, str) for x in audit)):
        _raise("intents.toml audit must be a list of strings")
    if platform == "openwrt":
        unknown_audit = [a for a in audit if a not in _AUDIT_IDS]
        if unknown_audit:
            _raise("intents.toml audit must be a list of AUDIT_ITEMS ids")
    if platform != "openwrt" and entry.get("control_id") not in ("", None):
        _raise("intents.toml has a control_id on a non-openwrt platform")
    if platform == "openwrt" and "control_id" in entry:
        control_id = entry["control_id"]
        if (not isinstance(control_id, str)
                or not _CONTROL_ID_RE.fullmatch(control_id)):
            _raise("intents.toml control_id must look like OW-XXXX-NN")
    for key in _SCALAR_KEYS + ("tier", "form_of"):
        v = entry.get(key, "" if key in _SCALAR_KEYS else None)
        if v is None:
            if key in _SCALAR_KEYS:
                entry[key] = ""
            continue
        if not isinstance(v, str):
            _raise("intents.toml has a non-string scalar field")
    if platform != "openwrt":
        _validate_vendor_intent_entry(entry, intent_id, platform)


def _validate_audit_against_enabled_getters(
    platform: str, audit: list[str],
) -> None:
    """A non-OpenWrt ``audit`` id must name a getter the platform
    ships ENABLED today (``adapters.enabled_getters(platform)``).
    A disabled getter (for example iosxe ``running_config``) is
    refused so the skill never tells the agent to read a getter that
    is itself refused at runtime. An unknown id is refused for the
    same reason."""
    enabled = set(enabled_getters(platform))
    for getter_id in audit:
        if getter_id not in enabled:
            _raise(
                f"intents.toml audit id {getter_id!r} is not an enabled "
                f"getter of {platform}"
            )


def _validate_snippet_pair(snippet: Any, confirm: Any) -> None:
    """``snippet`` and ``confirm`` must both be present or both absent.
    A single-side pairing (one without the other) is refused; the
    intent is to keep every revert-wrapped snippet paired with the
    human step that commits it before the wrapper's timer fires."""
    if (snippet is None) != (confirm is None):
        _raise(
            "intents.toml snippet and confirm must both be present or "
            "both absent"
        )


def _validate_snippet_is_service_off(intent_id: str, snippet: Any) -> None:
    """A snippet may only ride on a service-off intent (design 3.4,
    decision 9). The body of every shipped snippet is UNVERIFIED until
    a lab run confirms it on a lab device; this loader rule does
    not depend on the body being right, only on the intent being
    one of the four service-off ids."""
    if snippet is None:
        return
    if intent_id not in _SERVICE_OFF_INTENTS:
        _raise(
            f"intents.toml snippet on {intent_id!r}: only the four "
            f"service-off intents may carry a snippet"
        )


def _wrapper_line_matches(template: str, line: str) -> bool:
    """A wrapper template line may contain ``<short-name>`` slots;
    the snippet line has to match with any ``[^\\s]+`` filling each
    slot. Lines without slots must match literally."""
    parts = _SLOT_RE.split(template)
    if len(parts) == 1:
        return template == line
    pos = 0
    for index, part in enumerate(parts):
        if index % 2 == 0:
            if not line.startswith(part, pos):
                return False
            pos += len(part)
            continue
        m = re.match(r"[^\s]+", line[pos:])
        if m is None:
            return False
        pos += m.end()
    return pos == len(line)


_SLOT_RE = re.compile(r"<([a-z][a-z0-9-]{0,31})>")


def _validate_snippet_wrapper(platform: str, snippet: str) -> None:
    """The first lines and the trailing lines of ``snippet`` must
    match the platform's revert wrapper exactly (with ``<short-name>``
    slots filled by any non-whitespace value); everything in between
    counts as the body. Empty body (zero body lines) is refused
    because a body of zero lines carries no change and only burns the
    confirm window."""
    wrapper = _SNIPPET_WRAPPERS.get(platform)
    if wrapper is None:
        _raise(
            f"intents.toml snippet: no revert wrapper is defined for "
            f"{platform}"
        )
    try:
        body_index = wrapper.index("<BODY>")
    except ValueError:  # pragma: no cover - defined with BODY
        _raise(
            "internal error: snippet wrapper template missing <BODY> sentinel"
        )
    prefix = wrapper[:body_index]
    suffix = wrapper[body_index + 1:]
    lines = snippet.splitlines()
    if len(lines) < len(prefix) + len(suffix):
        _raise(
            "intents.toml snippet: too few lines to enclose the wrapper"
        )
    start = lines[: len(prefix)]
    end = lines[-len(suffix):] if suffix else []
    for tmpl, line in zip(prefix, start):
        if not _wrapper_line_matches(tmpl, line):
            _raise(
                "intents.toml snippet: opening wrapper does not match the "
                f"{platform} template"
            )
    for tmpl, line in zip(suffix, end):
        if not _wrapper_line_matches(tmpl, line):
            _raise(
                "intents.toml snippet: closing wrapper does not match the "
                f"{platform} template"
            )
    body = (
        lines[len(prefix): len(lines) - len(suffix)]
        if suffix else lines[len(prefix):]
    )
    if not body:
        _raise(
            "intents.toml snippet: body is empty (no command lines between "
            "the wrapper prefixes)"
        )
    if _SNIPPET_BANNED_WORDS_RE.search(snippet) is not None:
        _raise(
            "intents.toml snippet: contains a banned word (user|username|"
            "password|secret|key|keys|authentication|privilege|role|community"
            "|permit|allow|allowaccess|accept|forward|nat|vip|vpn|ipsec|"
            "tunnel|wireguard|trusthost|address|source|interface|route)"
        )
    if _SNIPPET_IPV4_RE.search(snippet) is not None:
        _raise("intents.toml snippet: contains an IPv4 literal")
    if _SNIPPET_IPV6_RE.search(snippet) is not None:
        _raise("intents.toml snippet: contains an IPv6 literal")
    if _SNIPPET_ANGLE_RE.search(snippet) is not None:
        _raise("intents.toml snippet: contains an angle-bracket placeholder")


def _validate_vendor_intent_entry(
    entry: dict[str, Any], intent_id: str, platform: str,
) -> None:
    """Validate the non-OpenWrt-only keys of an ``[[intent]]`` entry.
    Called only when ``platform != 'openwrt'``; OpenWrt entries skip
    every check here so the legacy v1 loader path is byte-identical."""
    audit = list(entry.get("audit") or [])
    _validate_audit_against_enabled_getters(platform, audit)

    check = _require_required_sentence(entry, intent_id, "check")
    good = _require_required_sentence(entry, intent_id, "good")

    snippet = entry.get("snippet")
    confirm = entry.get("confirm")
    if snippet is not None and not isinstance(snippet, str):
        _raise(
            f"intents.toml entry {intent_id!r}: snippet must be a string"
        )
    if confirm is not None and not isinstance(confirm, str):
        _raise(
            f"intents.toml entry {intent_id!r}: confirm must be a string"
        )
    _validate_snippet_pair(snippet, confirm)
    _validate_snippet_is_service_off(intent_id, snippet)
    if snippet is not None:
        _validate_snippet_wrapper(platform, snippet)
        _validate_confirm_command_text(platform, snippet, confirm)


def _require_required_sentence(
    entry: dict[str, Any], intent_id: str, key: str,
) -> str:
    """A non-OpenWrt ``check`` / ``good`` must be a present,
    non-empty string with no newline (it ships in a ``recommend()``
    JSON record where a multi-line value would break the contract).
    A missing key, an empty string, a newline, or any non-string
    value is refused with ``_raise``."""
    if key not in entry:
        _raise(
            f"intents.toml entry {intent_id!r}: {key} is required"
        )
    value = entry[key]
    if not isinstance(value, str):
        _raise(
            f"intents.toml entry {intent_id!r}: {key} must be a string"
        )
    if not value:
        _raise(
            f"intents.toml entry {intent_id!r}: {key} must be non-empty"
        )
    if "\n" in value:
        _raise(
            f"intents.toml entry {intent_id!r}: {key} must be a single "
            f"line (no newline)"
        )
    return value


_CONFIRM_REQUIRED_TEXT: dict[str, str] = {
    "junos": "commit",
    "iosxe": "configure confirm",
    "vyos": "confirm",
    "fortios": "execute cfg save",
    "routeros": "Ctrl-X",
}


def _validate_confirm_command_text(
    platform: str, snippet: str, confirm: str,
) -> None:
    """The ``confirm`` sentence must name the human step that
    commits the change before the platform's revert wrapper fires.
    The required fragment is per-platform; for EOS the session name
    in the confirm must equal the ``<short-name>`` slot in the
    snippet's first wrapper line so the operator runs the right
    ``configure session <name> commit``."""
    if platform == "eos":
        first_line = snippet.splitlines()[0]
        m = re.match(r"^configure session newton-(\S+)$", first_line)
        if m is None:
            _raise(
                "intents.toml eos snippet first line does not name a "
                "session (configure session newton-<name>)"
            )
        session = m.group(1)
        needed = f"configure session newton-{session} commit"
        if needed not in confirm:
            _raise(
                f"intents.toml eos confirm: must contain {needed!r}"
            )
        return
    required = _CONFIRM_REQUIRED_TEXT.get(platform)
    if required is None:
        return
    if platform == "junos":
        if "commit confirmed" in confirm:
            _raise(
                "intents.toml junos confirm: must not contain "
                "'commit confirmed' (the wrapper arms that itself)"
            )
    if required not in confirm:
        _raise(
            f"intents.toml {platform} confirm: must contain "
            f"{required!r}"
        )


# ---- intent -> recommendation (v2 report) ---------------------------------


def _v2_owner_reason(canonical: dict[str, Any], qid: str) -> str:
    """``"<v2 question text> (answer: <display>)"``. Display rules:
    enum -> str value; multi_enum -> items joined by ``", "`` or
    ``none``; port_list -> same; host_lists -> ``"syslog: a, b; ntp: c"``
    with ``"none"`` for an empty list. Unknown qid falls back to a
    placeholder."""
    q = _V2_BY_ID.get(qid)
    if q is None:
        return f"(unknown question {qid}) (answer: unknown)"
    return f"{q['text']} (answer: {_format_answer(q, canonical.get(qid))})"


def _format_answer(q: dict[str, Any], raw: Any) -> str:
    typ = q["type"]
    if typ == "enum":
        return str(raw)
    if typ in ("multi_enum", "port_list"):
        items = list(raw) if raw else []
        return ", ".join(items) if items else "none"
    if typ == "host_lists":
        if not isinstance(raw, dict):
            return "none"
        parts = [
            f"{k}: {', '.join(raw[k]) if raw.get(k) else 'none'}"
            for k in ("syslog", "ntp")
        ]
        return "; ".join(parts)
    return "?"


_UNMAPPED_RECORD: dict[str, Any] = {
    "guidance": "none", "audit": [], "control_id": None,
    "doc": "", "ledger": "",
}


def _build_intent_record(
    intent_id: str, intents_map: dict[str, dict[str, Any]], platform: str,
) -> tuple[dict[str, Any], str | None, str]:
    """Build one ``intents`` entry; returns ``(record, tier_selector,
    form_of)`` so the caller can build the matching
    ``recommendations`` entry.

    The record shape is platform-dependent:

    * OpenWrt: the seven contract keys
      ``{id, guidance, explanation, audit, control_id, doc, ledger}``
      (doc / ledger default to ``""``).  ``suggestion`` is not set.
    * Every other platform: the same seven keys plus an eighth,
      ``suggestion``.  An unmapped intent carries ``suggestion=None``
      and explanation ``no guidance for <platform> yet``; a mapped
      intent carries a dict with ``status = "UNVERIFIED"`` (every
      vendor snippet is unverified until a lab run) and the four
      rule fields ``check``, ``good``, ``snippet``, ``confirm``
      (the latter two are strings or ``None``).
    """
    if intent_id not in intents_map:
        record = {
            "id": intent_id,
            "explanation": f"no guidance for {platform} yet",
            **_UNMAPPED_RECORD,
        }
        if platform != "openwrt":
            record["suggestion"] = None
        return record, None, ""

    entry = intents_map[intent_id]
    control_id = entry.get("control_id") or None
    audit = list(entry.get("audit") or [])
    guidance = (
        "control" if control_id else ("audit" if audit else "none")
    )
    explanation = str(entry.get("explanation") or "")
    if guidance == "none":
        explanation = explanation or f"no guidance for {platform} yet"
    record = {
        "id": intent_id, "guidance": guidance, "explanation": explanation,
        "audit": audit, "control_id": control_id,
        "doc": str(entry.get("doc") or ""),
        "ledger": str(entry.get("ledger") or ""),
    }
    if platform != "openwrt":
        record["suggestion"] = _build_suggestion(entry)
    return record, entry.get("tier") or None, entry.get("form_of") or ""


def _build_suggestion(entry: dict[str, Any]) -> dict[str, Any]:
    """Build the eighth ``suggestion`` key for a non-OpenWrt mapped
    intent. The dict has ``status`` (always ``"UNVERIFIED"`` today
    because every vendor command set is UNVERIFIED until a lab
    capture measures it on a device), ``check``, ``good`` (both
    required strings from the file), and ``snippet`` / ``confirm``
    (each either the entry's value or ``None``; both or neither).
    """
    snippet = entry.get("snippet")
    confirm = entry.get("confirm")
    return {
        "status": "UNVERIFIED",
        "check": str(entry.get("check") or ""),
        "good": str(entry.get("good") or ""),
        "snippet": str(snippet) if snippet is not None else None,
        "confirm": str(confirm) if confirm is not None else None,
    }


# ---- v2 report builder ----------------------------------------------------


# v2 path uses the same tier map as the legacy path; one source of truth.
_STRICTNESS_TO_TIER = LEGACY_STRICTNESS_TIER


def _v2_recommend(
    canonical: dict[str, Any], *,
    controls: list[dict[str, Any]] | None = None,
    directory: Path | None = None, platform: str,
) -> dict[str, Any]:
    tier = _STRICTNESS_TO_TIER[canonical["strictness"]]
    all_controls = _load_all_controls(controls)
    if directory is None:
        directory = Path(probes.manifest_path()).parent
    intents_map = load_intents(platform=platform, directory=directory)

    # Resolve intents in question order, then build the matching
    # recommendations in the same order via the shared helper.
    intents: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []
    for q in QUESTIONS:
        qid = q["id"]
        if qid == "strictness":
            continue
        value = canonical.get(qid)
        if value is None:
            continue
        for intent_id in _V2_INTENTS_FOR_QUESTION.get(qid, lambda _v: [])(value):
            record, intent_tier, intent_form_of = _build_intent_record(
                intent_id, intents_map, platform,
            )
            intents.append(record)
            if record["control_id"] is not None:
                recommendations.append(_build_recommendation_dict(
                    control_id=record["control_id"],
                    tier_selector=intent_tier,
                    form_of=intent_form_of,
                    report_tier=tier,
                    owner_reason=_v2_owner_reason(canonical, qid),
                    controls=all_controls, directory=directory,
                ))

    report = _empty_v1_report_skeleton(tier)
    for q in QUESTIONS:
        qid = q["id"]
        if qid in canonical:
            report["answers"].append({"id": qid, "answer": canonical[qid]})
        else:
            report["unanswered"].append(qid)
    report["unanswered"].sort()
    report["recommendations"] = recommendations
    report["intents"] = intents
    return report


# ---- public API: recommend ------------------------------------------------


def recommend(
    answers: Any,
    *,
    controls: list[dict[str, Any]] | None = None,
    directory: Path | None = None,
    platform: str = "openwrt",
) -> dict[str, Any]:
    """Build a report from interview answers.

    A legacy dict (v1 ids, string values) returns the byte-stable
    v1 ``guided_setup_report``. Any other dict is v2: it is
    validated, aliases folded, and a v2 report is built for
    ``platform``.
    """
    if not isinstance(answers, dict):
        _raise("answers must be a dict of question id -> answer value")
    if platform == "openwrt" and _is_legacy_input(answers):
        return _legacy_recommend(
            answers, controls=controls, directory=directory,
        )
    canonical = normalize(answers)
    if not _PLATFORM_RE.fullmatch(platform):
        _raise("platform id has an invalid shape")
    return _v2_recommend(
        canonical,
        controls=controls,
        directory=directory,
        platform=platform,
    )


# ---- public API: summary --------------------------------------------------


_DEVICE_KIND_LINES = {
    "home_router": "This device is a home router.",
    "office_firewall": "This device is an office firewall.",
    "switch": "This device is a managed switch.",
    "edge_router": "This device is an edge router.",
    "not_sure": "Device kind is unclear.",
}
_STRICTNESS_LINES = {
    "normal":   "Strictness: normal home use (standard tier).",
    "stricter": "Strictness: stricter, even if some convenience breaks (hardened tier).",
    "maximum":  "Strictness: maximum restriction (lockdown tier).",
}
_ADMIN_SOURCE_LINES = {
    "lan_only":     "Admins log in from the LAN only.",
    "mgmt_network": "Admins log in from the management network only.",
    "vpn_only":     "Admins log in over a VPN only.",
    "anywhere":     "Warning: any admin source opens the router to the whole internet. Admins log in from anywhere.",
}
_ADMIN_ACCESS_OPEN = "Admin access stays on for: {items}."
_ADMIN_ACCESS_OFF = "Admin access stays off entirely."
_ADMIN_ACCESS_WARNINGS = {
    "telnet":    "Warning: telnet sends passwords in clear text.",
    "snmp_v1v2": "Warning: SNMP v1/v2 has weak authentication.",
}
_SSH_PASSWORD_LINES = {"yes": "SSH passwords go off; keys only.",
                       "no":  "SSH passwords stay allowed."}
_INBOUND_LIST_PREFIX = "These services may reach in from the internet: "
_INBOUND_NONE = "Nothing may reach in from the internet."
_UPNP_LINES = {"yes": "UPnP/NAT-PMP stays on.", "no": "UPnP/NAT-PMP stays off."}
_SEGMENTS_PREFIX = "Separate segments: "
_SEGMENTS_NONE = "No separate segments."
_WIFI_WPA2_LINES = {
    "yes":      "Wi-Fi keeps WPA2 compatibility.",
    "unsure":   "Wi-Fi keeps WPA2 compatibility because old devices may join.",
    "all_wpa3": "Wi-Fi runs WPA3 only; older devices cannot join.",
}
_DNS_PREFIX = "DNS settings on: "
_DNS_NONE = "No DNSSEC, no encrypted DNS."
_IPV6_OFF_LINES = {"yes": "IPv6 is off.", "no": "IPv6 stays on.",
                   "unsure": "IPv6 status: unsure."}
_REMOTE_VPN_LINES = {
    "none":         "No remote-access VPN.",
    "site_to_site": "Site-to-site VPN is in use.",
    "road_warrior": "Road-warrior VPN is in use.",
}
_FW_UPDATE_LINES = {
    "yes": "Firmware-update availability check stays on.",
    "no":  "Firmware-update availability check stays off.",
}


_HUMANISE_MAP = {
    "ssh": "SSH", "web_ui": "web UI", "api": "API", "telnet": "telnet",
    "snmp_v3": "SNMP v3", "snmp_v1v2": "SNMP v1/v2",
    "dnssec": "DNSSEC", "encrypted": "encrypted DNS",
}


def _humanise(items: list[str]) -> list[str]:
    return [_HUMANISE_MAP.get(it, it) for it in items]


def _summary_admin_access(items: list[str]) -> str:
    if not items:
        return _ADMIN_ACCESS_OFF
    parts = [_ADMIN_ACCESS_OPEN.format(items=", ".join(_humanise(items)))]
    parts.extend(m for k, m in _ADMIN_ACCESS_WARNINGS.items() if k in items)
    return " ".join(parts)


_PHRASE_TABLE = {
    "device_kind": _DEVICE_KIND_LINES, "strictness": _STRICTNESS_LINES,
    "admin_source": _ADMIN_SOURCE_LINES,
    "ssh_password_off": _SSH_PASSWORD_LINES,
    "upnp": _UPNP_LINES, "wifi_wpa2": _WIFI_WPA2_LINES,
    "ipv6_off": _IPV6_OFF_LINES, "remote_vpn": _REMOTE_VPN_LINES,
    "fw_update_check": _FW_UPDATE_LINES,
}
_LIST_PREFIX = {
    "inbound_services": _INBOUND_LIST_PREFIX,
    "segments": _SEGMENTS_PREFIX, "dns": _DNS_PREFIX,
}
_LIST_NONE = {
    "inbound_services": _INBOUND_NONE,
    "segments": _SEGMENTS_NONE, "dns": _DNS_NONE,
}


def _summary_log_time_hosts(value: dict[str, Any]) -> str:
    syslog_items = list(value.get("syslog") or [])
    ntp_items = list(value.get("ntp") or [])
    if not syslog_items and not ntp_items:
        return "No remote syslog or NTP servers."
    parts: list[str] = []
    if syslog_items:
        parts.append(f"Syslog goes to: {', '.join(syslog_items)}")
    if ntp_items:
        parts.append(f"NTP servers: {', '.join(ntp_items)}")
    return ". ".join(parts) + "."


def summary(answers: Any) -> str:
    """One plain English line per answered v2 question in question order,
    joined by ``"\n"``."""
    canonical = normalize(answers)
    lines: list[str] = []
    for q in QUESTIONS:
        qid = q["id"]
        if qid not in canonical:
            continue
        value = canonical[qid]
        phrase = _PHRASE_TABLE.get(qid)
        if phrase is not None:
            lines.append(phrase[value])
            continue
        if qid == "admin_access":
            lines.append(_summary_admin_access(list(value)))
        elif qid == "log_time_hosts":
            lines.append(_summary_log_time_hosts(value))
        elif qid in _LIST_PREFIX:
            items = list(value)
            if not items:
                lines.append(_LIST_NONE[qid])
                continue
            humanised = _humanise(items) if qid in ("segments", "dns") else items
            lines.append(_LIST_PREFIX[qid] + ", ".join(humanised) + ".")
    return "\n".join(lines)


# ---- confirmation record / store / status ---------------------------------


CONFIRMATION_TTL = timedelta(hours=24)


def confirmation_record(
    answers: Any,
    summary_text: str,
    *,
    device: str,
    platform: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Normalize ``answers`` and build a confirmation record dict.

    ``id`` is the lower-case hex sha256 of canonical answers plus
    summary, device and platform (sort_keys, compact separators).
    ``expires_at`` is ``created_at + CONFIRMATION_TTL``. The record
    is not stored on disk.
    """
    canonical = normalize(answers)
    if not _PLATFORM_RE.fullmatch(platform):
        _raise("platform id has an invalid shape")
    if not isinstance(device, str) or not device:
        _raise("device must be a non-empty string")
    if not isinstance(summary_text, str):
        _raise("summary must be a string")

    payload = {
        "answers": canonical,
        "summary": summary_text,
        "device": device,
        "platform": platform,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    cid = hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    when = now or datetime.now(timezone.utc)
    expires = when + CONFIRMATION_TTL

    answers_echo = [
        {"id": q["id"], "answer": canonical[q["id"]]}
        for q in QUESTIONS if q["id"] in canonical
    ]
    return {
        "id": cid,
        "answers": answers_echo,
        "summary": summary_text,
        "device": device,
        "platform": platform,
        "created_at": when.isoformat(),
        "expires_at": expires.isoformat(),
        "confirmed": False,
    }


def store_confirmation(
    record: dict[str, Any],
    state_root: Path,
) -> Path:
    """Write the record to ``<state_root>/guided-confirmations/<id>.json``.

    ``state_root`` is created with mode 0o700 the first time this call
    runs (``mkdir`` then ``chmod``, mirroring ``server.write_audit``,
    so the audit log and the confirmation store cannot leak across
    users on a shared host).  ``guided-confirmations/`` is also 0o700;
    the record file is written atomically via ``tempfile.mkstemp``
    (creates 0o600) then ``os.replace``.  Removes other records whose
    ``expires_at`` is past; same content stored again just rewrites it
    with the new expiry.
    """
    cid = record.get("id")
    if not isinstance(cid, str) or not _CONF_ID_RE.fullmatch(cid):
        _raise("confirmation record id is not a lower-case hex sha256")

    state_path = Path(state_root)
    refusal = _receipts.check_state_write_path(state_path, state_path)
    if refusal is not None:
        _raise(refusal)
    created = not state_path.exists()
    state_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created:
        os.chmod(state_path, 0o700)

    store_dir = state_path / "guided-confirmations"
    refusal = _receipts.check_state_dir_parent(store_dir)
    if refusal is not None:
        _raise(refusal)
    store_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(store_dir, 0o700)

    created_at = record.get("created_at")
    if not isinstance(created_at, str):
        _raise("confirmation record missing created_at")

    # Prune expired records. Only files ending in ``.json`` are
    # touched; the record we are about to write does not exist yet,
    # so it cannot be deleted here.
    now_dt = datetime.fromisoformat(created_at)
    for stale in list(store_dir.glob("*.json")):
        if stale.name == f"{cid}.json":
            # Defensive: even though we haven't written the target yet,
            # never delete the record matching the id we are storing.
            continue
        try:
            stale_data = json.loads(stale.read_text(encoding="utf-8"))
        except Exception:
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
            continue
        try:
            stale_expiry = datetime.fromisoformat(stale_data.get("expires_at", ""))
        except Exception:
            stale_expiry = None
        if stale_expiry is not None and stale_expiry < now_dt:
            try:
                stale.unlink()
            except FileNotFoundError:
                pass

    target = store_dir / f"{cid}.json"
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
    # Atomic write: mkstemp creates a 0o600 temp file with a unique
    # name (so a leftover temp from a crashed prior write cannot
    # block this one), then ``os.replace`` renames it into place.
    fd, tmp_str = tempfile.mkstemp(
        dir=store_dir, prefix=".conf-", suffix=".tmp",
    )
    tmp_target = Path(tmp_str)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp_target, target)
    except Exception:
        try:
            tmp_target.unlink()
        except FileNotFoundError:
            pass
        raise
    return target


def confirmation_status(
    conf_id: str,
    state_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, str]:
    """Return ``{"id", "status"}`` for one stored confirmation.

    ``"valid"`` when the file exists and ``expires_at`` is in the
    future, ``"expired"`` when it has passed, ``"unknown"`` for a
    missing file or an id that does not match the lower-case hex
    sha256 shape (so a traversal-style id never reaches disk).
    """
    if not isinstance(conf_id, str) or not _CONF_ID_RE.fullmatch(conf_id):
        return {"id": conf_id, "status": "unknown"}
    store_dir = Path(state_root) / "guided-confirmations"
    target = store_dir / f"{conf_id}.json"
    if not target.exists():
        return {"id": conf_id, "status": "unknown"}
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return {"id": conf_id, "status": "unknown"}
    expires_at = data.get("expires_at")
    if not isinstance(expires_at, str):
        return {"id": conf_id, "status": "unknown"}
    try:
        expires_dt = datetime.fromisoformat(expires_at)
    except Exception:
        return {"id": conf_id, "status": "unknown"}
    compare = now or datetime.now(timezone.utc)
    if expires_dt <= compare:
        return {"id": conf_id, "status": "expired"}
    return {"id": conf_id, "status": "valid"}
