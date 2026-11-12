"""The owner's network rules: load ``rules.toml`` and map rules to claims.

A network rule is a short statement the OWNER writes about a device's
network that must stay true, e.g. "from the iot zone, the router admin
is blocked".  Rules live in ``rules.toml`` next to the inventory
``devices.toml`` (same directory, same owner: the MCP server's user) and
only the owner writes them (``scripts/newton-rules``, run as the newton
user like ``newton-enrol``); no MCP tool can.  This module is the read
side the server and the plan path share.

Only pure functions live here: no ssh, no device, no vantage.  The file
is loaded with the inventory's own file checks
(``inventory_file.check``), a file that is not exactly the contract is
refused whole (the server then refuses plans on every device until the
owner fixes it; reads still work), and each rule maps to the client
claim a plan carries, marked ``source: rule``.

A rule never carries free text that reaches a shell or the model
unescaped: the words Newton shows are built from the fields, and the
optional ``label`` is validated to a safe alphabet and shown, never
executed or sealed into a probe.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import inventory_file as inventory_file_module
from .client_checks import valid_target
from .scans import NAME_RE, ZONE_RE

#: The file name of the rules, next to ``devices.toml``.
RULES_FILE_NAME = "rules.toml"

RULE_ID_RE = re.compile(r"^[a-z0-9-]{1,32}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9 ,.'()-]{1,80}$")

#: The rule kinds and their fixed claim kinds.  ``blocked`` and ``reach``
#: carry a ``to`` and map to ``client_blocked`` / ``client_reaches``.
KINDS = ("dns", "dhcp", "internet", "blocked", "reach")
KIND_TO_CLAIM = {
    "dns": "client_dns",
    "dhcp": "client_dhcp",
    "internet": "client_internet",
}

#: Max rules per device; the 17th is refused at add time and at load.
MAX_RULES_PER_DEVICE = 16

RULE_KEYS = frozenset({"id", "device", "zone", "kind", "to", "label"})
REQUIRED_KEYS = frozenset({"id", "device", "zone", "kind"})


class NetRuleError(ValueError):
    """The rules file could not be loaded.  The message is safe to show."""


@dataclass(frozen=True)
class Rule:
    """One owner-written rule, already validated."""

    id: str
    device: str
    zone: str
    kind: str
    to: str | None = None
    label: str | None = None


def rules_path(inventory: Path) -> Path:
    """``rules.toml`` lives next to ``devices.toml``, with the same owner."""
    return Path(inventory).parent / RULES_FILE_NAME


def _refuse(where: str, message: str) -> None:
    raise NetRuleError(f"{where}: {message}")


def _rule_from_table(index: int, raw: Any) -> Rule:
    """One ``[[rule]]`` table, validated field by field.

    A refusal names the rule (by id when the id is usable, by position
    when it is not) and the field.
    """
    where = f"rule #{index}"
    if not isinstance(raw, dict):
        _refuse(where, "a rule must be a table")
    rule_id = raw.get("id")
    if isinstance(rule_id, str) and RULE_ID_RE.fullmatch(rule_id):
        where = f"rule {rule_id}"
    unknown = sorted(set(raw) - RULE_KEYS)
    if unknown:
        _refuse(where, f"unknown keys: {', '.join(unknown)}")
    missing = sorted(REQUIRED_KEYS - set(raw))
    if missing:
        _refuse(where, f"missing required keys: {', '.join(missing)}")
    for field, regex in (("id", RULE_ID_RE), ("device", NAME_RE), ("zone", ZONE_RE)):
        value = raw.get(field)
        if not isinstance(value, str) or regex.fullmatch(value) is None:
            _refuse(where, f"{field} must match {regex.pattern}")
    kind = raw.get("kind")
    if kind not in KINDS:
        _refuse(where, f"kind must be one of {', '.join(KINDS)}")
    label = raw.get("label")
    if label is not None and (
        not isinstance(label, str) or LABEL_RE.fullmatch(label) is None
    ):
        _refuse(where, "label must be 1-80 characters of [A-Za-z0-9 ,.'()-]")
    to = raw.get("to")
    if kind in KIND_TO_CLAIM:
        if to is not None:
            _refuse(where, f"kind {kind} must not carry to")
    elif kind == "blocked":
        if to not in ("router", "internet") and not valid_target(to):
            _refuse(
                where,
                'kind blocked requires to of "router", "internet" or "<ipv4>:<port>"',
            )
    else:  # reach
        if not valid_target(to):
            _refuse(where, 'kind reach requires to of "<ipv4>:<port>"')
    return Rule(
        id=rule_id,
        device=raw["device"],
        zone=raw["zone"],
        kind=kind,
        to=to,
        label=label,
    )


def load_rules(
    path: Path, known_devices: set[str] | None = None
) -> dict[str, tuple[Rule, ...]]:
    """Load ``rules.toml``, keyed by device, in file order.

    The file is checked the way the inventory is (a regular file, not a
    symlink, not group- or world-writable, owned by the server user); a
    missing file is simply no rules.  ``known_devices`` (the inventory's
    device names) refuses a rule for a device that does not exist.  Any
    violation refuses the whole file.
    """
    path = Path(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise NetRuleError(f"rules file cannot be inspected: {exc.strerror}") from None
    message = inventory_file_module.check(path)
    if message is not None:
        raise NetRuleError(message)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise NetRuleError(f"invalid rules file: {exc}") from exc
    unknown_top = sorted(set(data) - {"rule"})
    if unknown_top:
        raise NetRuleError(f"rules file has unknown keys: {', '.join(unknown_top)}")
    raw_rules = data.get("rule", [])
    if not isinstance(raw_rules, list):
        raise NetRuleError("rules file: rule must be a list of tables")
    by_device: dict[str, list[Rule]] = {}
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_rules, start=1):
        rule = _rule_from_table(index, raw)
        if rule.id in seen_ids:
            _refuse(f"rule {rule.id}", "id must be unique per file")
        seen_ids.add(rule.id)
        if known_devices is not None and rule.device not in known_devices:
            _refuse(f"rule {rule.id}", f"device {rule.device} is not in the inventory")
        by_device.setdefault(rule.device, []).append(rule)
    for device, rules in by_device.items():
        if len(rules) > MAX_RULES_PER_DEVICE:
            raise NetRuleError(
                f"device {device} has {len(rules)} rules; "
                f"the cap is {MAX_RULES_PER_DEVICE}"
            )
    return {device: tuple(rules) for device, rules in by_device.items()}


def rule_claims(rules: Iterable[Rule]) -> list[dict[str, Any]]:
    """The client claims the plan carries for these rules, in order.

    Each claim is marked ``source: rule`` and ``rule: <id>``; the
    targets of a claim are filled later by ``client_checks.fill_targets``
    exactly like an agent claim's, so both are sealed into the plan hash
    the same way.  The label is never part of a claim.
    """
    claims: list[dict[str, Any]] = []
    for rule in rules:
        if rule.kind in KIND_TO_CLAIM:
            kind = KIND_TO_CLAIM[rule.kind]
        elif rule.kind == "blocked":
            kind = "client_blocked"
        else:
            kind = "client_reaches"
        claim: dict[str, Any] = {
            "kind": kind,
            "zone": rule.zone,
            "source": "rule",
            "rule": rule.id,
        }
        if rule.kind in ("blocked", "reach"):
            claim["to"] = rule.to
        claims.append(claim)
    return claims


def rule_sentence(rule: Rule) -> str:
    """The words Newton shows for one rule, built from the fields only.

    No device data and no owner label is part of the sentence: the label
    is shown beside it, never inside it.
    """
    where = f"from {rule.zone}: "
    if rule.kind == "dns":
        return where + "DNS names resolve through the zone router"
    if rule.kind == "dhcp":
        return where + "DHCP offers arrive from the zone router"
    if rule.kind == "internet":
        return where + "the internet is reachable"
    if rule.kind == "blocked":
        if rule.to == "router":
            return where + "router admin blocked"
        if rule.to == "internet":
            return where + "the internet is blocked"
        return where + f"{rule.to} blocked"
    return where + f"{rule.to} reachable"
