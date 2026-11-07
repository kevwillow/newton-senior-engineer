"""the ops of an owner script, and the grammar they must pass.

ADR-021 point 7 and the design.  A no-install router gets a change
Newton may not apply itself through a script the owner approves byte
for byte.  This module turns the agent's uci batch into the ops that
script may carry, and it refuses everything else.

The rules, and why each one is here:

  * only ``set``, ``add_list``, ``del_list`` and ``delete`` are allowed.
    An anonymous ``add`` has no name the script could point at, so the
    way to add a section is ``set CFG.NAME=TYPE`` with a name uci
    accepts;
  * only the configs the router's own web API may read are allowed, so
    every change Newton makes can be backed up and read back;
  * an option whose name says "secret" is refused: the script bytes are
    shown to the owner in full, and the owner approves them, so a
    secret must never be in them;
  * every value must be printable ASCII without a quote, so it can be
    written inside single quotes and can never become shell code;
  * the policy reasons that make a change impossible to confirm from
    the address Newton reaches the router on are refused, and the rest
    stay as the plan's reasons and risk.

Nothing here touches a router, a file or the network: this module is
pure logic over a backup and a batch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from . import policy
from . import redact
from . import undo
from .rpcd_txn import ADDED_NAME_RE


class OwnerScriptError(Exception):
    """A refusal of an owner script.

    The message may name a config, a section or an option.  It never
    echoes a value: a value can hold a secret, and a value that came
    from the router is untrusted text.
    """


#: The configs the rpcd user may read, and therefore the only ones
#: Newton can back up and read back.
ALLOWED_CONFIGS: tuple[str, ...] = ("dhcp", "firewall", "network", "system", "wireless")

#: The verbs an owner script may carry.
ALLOWED_VERBS: tuple[str, ...] = ("set", "add_list", "del_list", "delete")

#: The most ops one script may carry.
MAX_OPS = 50

#: The most bytes one value may have.
MAX_VALUE_BYTES = 512

#: The characters a shell acts on.  A value that holds one of them is
#: refused even though the script quotes every value with single
#: quotes: the script's bytes are shown to the owner and approved, and
#: a value a shell could act on has no place in an approved script.
SHELL_ACTIVE_CHARS = "$`\\;&|<>(){}"

#: The policy reason codes that make a change impossible to confirm
#: from the address Newton reaches the router on, or impossible to
#: check at all.  The owner flow refuses them; the rest stay as the plan's reasons.
REFUSED_REASONS: tuple[str, ...] = (
    "exec-include",
    "exec-option",
    "exec-config",
    "unknown-package",
    "section-unidentified",
    "mgmt-config",
    "mgmt-zone",
    "mgmt-interface",
    "forwarding-mgmt",
    "mgmt-route",
)

#: The refusal for a config Newton cannot read.
CONFIG_REFUSAL = (
    "not available in no-install access in this version: Newton cannot read it, "
    "so it cannot back it up or check it"
)

#: The refusal for an option whose name says "secret".
SECRET_REFUSAL = "set it yourself in LuCI; Newton does not put secrets in a script"

#: The refusal for a value that cannot be written into a script safely.
UNSAFE_VALUE_REFUSAL = "the value of {unit} cannot be written into a script safely"

#: The refusal for a router value that cannot be written into a check.
UNSAFE_CHECK_REFUSAL = "Newton cannot write a safe check for {unit}"

#: The name of the section a restore script re-creates.
RESTORE_NAME_PREFIX = "newton_r_"

#: A unit of a config: the config, the section and the option.
Unit = tuple[str, str, str | None]

#: An ``@TYPE[K]`` address, as uci writes it.
_ANON_RE = re.compile(r"^@([A-Za-z0-9_-]{1,32})\[(-?[0-9]{1,3})\]$")


@dataclass(frozen=True)
class OwnerOp:
    """One change an owner script may carry."""

    verb: str
    config: str
    section: str
    option: str | None = None
    value: str | None = None
    type: str | None = None


# ---- the value grammar -----------------------------------------------------


def check_value(value: object) -> bool:
    """True when the value can be written inside single quotes safely.

    Printable ASCII only (0x20 to 0x7E), at most 512 bytes, and never a
    single quote: the script quotes every value with single quotes, so
    a quote inside one would end the quoting and the rest of the value
    would become shell code.
    """
    if not isinstance(value, str) or not value:
        return False
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if len(raw) > MAX_VALUE_BYTES:
        return False
    if not all(0x20 <= byte <= 0x7E for byte in raw):
        return False
    if "'" in value:
        return False
    return not set(value) & set(SHELL_ACTIVE_CHARS)


# ---- the backup's shape ----------------------------------------------------


def _sections(before: Any, config: str) -> Mapping[str, Any]:
    configs = getattr(before, "configs", None)
    if not isinstance(configs, Mapping):
        return {}
    sections = configs.get(config)
    if not isinstance(sections, Mapping):
        return {}
    return sections


def _entry(before: Any, config: str, section: str) -> Mapping[str, Any] | None:
    entry = _sections(before, config).get(section)
    return entry if isinstance(entry, Mapping) else None


def _current(before: Any, config: str, section: str, option: str) -> Any:
    """The value of one option as the backup holds it.

    A list option is a tuple of its items, in the order the router
    answered them.  ``None`` means the option is not there.
    """
    entry = _entry(before, config, section)
    if entry is None or option not in entry:
        return None
    value = entry[option]
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def _section_type(before: Any, config: str, section: str) -> str | None:
    entry = _entry(before, config, section)
    if entry is None:
        return None
    value = entry.get(".type")
    return value if isinstance(value, str) and value else None


def _section_index(before: Any, config: str, section: str) -> int | None:
    entry = _entry(before, config, section)
    if entry is None:
        return None
    value = entry.get(".index")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _resolve_anonymous(before: Any, config: str, address: str) -> str:
    """The name the router gave to the section an ``@TYPE[K]`` names."""
    match = _ANON_RE.fullmatch(address)
    if match is None:
        raise OwnerScriptError(f"the section address {address} is not one uci writes")
    section_type = match.group(1)
    # uci counts from 0, and from the end with a minus sign (measured on
    # lab-r1: @zone[1] is the second zone, @dnsmasq[-1] the last one).
    position = int(match.group(2))
    named = [
        entry
        for entry in _sections(before, config).values()
        if isinstance(entry, Mapping) and entry.get(".type") == section_type
    ]
    named.sort(key=lambda item: item.get(".index", 0))
    if not -len(named) <= position < len(named):
        raise OwnerScriptError(
            f"the section {address} does not exist on the router"
        )
    entry = named[position]
    name = entry.get(".name")
    if not isinstance(name, str) or not name:
        raise OwnerScriptError(
            f"the section {address} does not exist on the router"
        )
    return name


# ---- the ops ---------------------------------------------------------------


def op_key(op: OwnerOp) -> str:
    """The path of the unit an op touches."""
    if op.option is None:
        return f"{op.config}.{op.section}"
    return f"{op.config}.{op.section}.{op.option}"


def op_value(op: OwnerOp) -> str | None:
    """The value an op writes, or None when it writes none."""
    if op.verb == "reorder":
        return op.value
    if op.option is None:
        return op.type if op.verb == "set" else None
    return op.value


def to_script_ops(ops: Sequence[OwnerOp]) -> tuple[tuple[str, str, str | None], ...]:
    """The ops in the shape a rendered script carries them."""
    return tuple((op.verb, op_key(op), op_value(op)) for op in ops)


def ops_of(record: Mapping[str, Any]) -> list[OwnerOp]:
    """The ops of a record, as the ops of the grammar.

    The record carries the ops of its change as ``(verb, key, value)``
    triples, so the work that follows works from the record alone and
    never has to trust a script on disk.
    """
    raw = record.get("ops")
    if not isinstance(raw, list):
        raise OwnerScriptError("the plan record carries no ops")
    ops: list[OwnerOp] = []
    for entry in raw:
        if not isinstance(entry, (list, tuple)) or len(entry) != 3:
            raise OwnerScriptError("the plan record carries a malformed op")
        verb, key, value = entry
        parts = str(key).split(".")
        if len(parts) not in (2, 3):
            raise OwnerScriptError("the plan record carries a malformed op")
        config, section = parts[0], parts[1]
        option = parts[2] if len(parts) == 3 else None
        if option is None and verb == "set":
            ops.append(OwnerOp(verb, config, section, None, None, str(value)))
        else:
            ops.append(OwnerOp(verb, config, section, option, value, None))
    return ops


def batch_lines(ops: Sequence[OwnerOp]) -> list[str]:
    """The uci batch lines of the ops, in order."""
    lines: list[str] = []
    for op in ops:
        key = op_key(op)
        if op.verb == "set":
            if op.option is None:
                lines.append(f"set {key}={op.type}")
            else:
                lines.append(f"set {key}='{op.value}'")
        elif op.verb == "add_list":
            lines.append(f"add_list {key}='{op.value}'")
        elif op.verb == "del_list":
            lines.append(f"del_list {key}='{op.value}'")
        elif op.verb == "delete":
            lines.append(f"delete {key}")
        elif op.verb == "reorder":
            lines.append(f"reorder {key}={op.value}")
        else:  # pragma: no cover - the constructors are the only way in
            raise OwnerScriptError(f"unknown verb {op.verb!r}")
    return lines


def _raw_unit(line: str) -> str | None:
    """The path of a line that cannot be read, for the refusal."""
    match = re.match(r"^\s*[A-Za-z_]+\s+([A-Za-z0-9_.@-]+)", line)
    return match.group(1) if match else None


def _parse_line(line: str, before: Any) -> OwnerOp:
    """One batch line into one op, or a refusal."""
    if "<redacted:" in line:
        raise OwnerScriptError(
            "a placeholder cannot go into an owner script: the value must be "
            "written out in full"
        )
    try:
        words = undo._batch_words(line)
    except undo.UndoError:
        unit = _raw_unit(line)
        raise OwnerScriptError(
            f"the change of {unit} cannot be read" if unit else
            "a line of the change cannot be read"
        ) from None
    verb = words[0]
    if verb == "add":
        raise OwnerScriptError("add a named section: `set CFG.NAME=TYPE`")
    if verb not in ALLOWED_VERBS:
        raise OwnerScriptError(
            "only " + ", ".join(ALLOWED_VERBS) + " are allowed in an owner script"
        )
    if len(words) != 2:
        raise OwnerScriptError(
            "every line of an owner script is one verb and one argument"
        )
    argument = words[1]
    path, separator, raw_value = argument.partition("=")
    if not separator:
        raw_value = None
    parts = path.split(".")
    if len(parts) == 2:
        config, section, option = parts[0], parts[1], None
    elif len(parts) == 3:
        config, section, option = parts
    else:
        raise OwnerScriptError(
            "a change must name a config, a section and an option"
        )
    if policy.CONFIG_NAME_RE.fullmatch(config) is None:
        raise OwnerScriptError("the config name fails the UCI grammar")
    if config not in ALLOWED_CONFIGS:
        raise OwnerScriptError(f"{config} is {CONFIG_REFUSAL}")
    if section.startswith("@"):
        section = _resolve_anonymous(before, config, section)
    if policy.SECTION_NAME_RE.fullmatch(section) is None:
        raise OwnerScriptError("the section name fails the UCI grammar")
    if option is not None and policy.OPTION_NAME_RE.fullmatch(option) is None:
        raise OwnerScriptError("the option name fails the UCI grammar")
    if option is not None and redact._looks_like_secret_option(option):
        raise OwnerScriptError(SECRET_REFUSAL)

    if option is None:
        # a section-level op: `set CFG.SEC=TYPE` or `delete CFG.SEC`
        if verb != "set" and verb != "delete":
            raise OwnerScriptError(
                "only set and delete may name a whole section"
            )
        if verb == "delete":
            if _entry(before, config, section) is None:
                raise OwnerScriptError(
                    f"the section {config}.{section} does not exist on the router"
                )
            return OwnerOp("delete", config, section, None, None, None)
        section_type = raw_value
        if section_type is None:
            raise OwnerScriptError("a new section needs its type")
        if policy.SECTION_TYPE_RE.fullmatch(section_type) is None:
            raise OwnerScriptError("the section type fails the UCI grammar")
        if not check_value(section_type):
            raise OwnerScriptError(
                UNSAFE_VALUE_REFUSAL.format(unit=f"{config}.{section}")
            )
        existing = _entry(before, config, section)
        if existing is None:
            if ADDED_NAME_RE.fullmatch(section) is None:
                raise OwnerScriptError(
                    f"a new section needs a name of lowercase letters, digits and "
                    f"underscores: {config}.{section}"
                )
        else:
            known = _section_type(before, config, section)
            if known is not None and known != section_type:
                raise OwnerScriptError(
                    f"the batch changes the type of {config}.{section} from "
                    f"{known} to {section_type}; Newton does not do that"
                )
        return OwnerOp("set", config, section, None, None, section_type)

    # an option-level op
    if raw_value is None:
        if verb != "delete":
            raise OwnerScriptError(
                "a change to an option needs a value; use delete to remove one"
            )
        return OwnerOp("delete", config, section, option, None, None)
    if not check_value(raw_value):
        raise OwnerScriptError(
            UNSAFE_VALUE_REFUSAL.format(unit=f"{config}.{section}.{option}")
        )
    if verb == "delete":
        raise OwnerScriptError(
            "a delete takes no value; use delete CFG.SECTION.OPTION"
        )
    return OwnerOp(verb, config, section, option, raw_value, None)


def _reason_code(reason: str) -> str:
    """The code of a policy reason: the word before the colon."""
    return reason.split(":", 1)[0].strip()


def _unit_list(ops: Sequence[OwnerOp]) -> str:
    units = [op_key(op) for op in ops]
    if len(units) <= 5:
        return ", ".join(units)
    return ", ".join(units[:5]) + f" and {len(units) - 5} more"


def parse_batch(uci_batch: str, before: Any, device: Any) -> list[OwnerOp]:
    """The ops of an owner script, or a refusal of the whole batch.

    The batch is the same uci batch text the agent sends to
    ``newton_plan_change``.  Every line becomes one op; the first line
    that breaks a rule refuses the whole batch, because a script that
    carries half a change is worse than no script.
    """
    if not isinstance(uci_batch, str):
        raise OwnerScriptError("the change must be text")
    lines = [
        line.strip()
        for line in uci_batch.split("\n")
        if line.strip() and not line.strip().startswith("#")
    ]
    if not lines:
        raise OwnerScriptError("the change is empty: there is nothing to put in a script")
    ops: list[OwnerOp] = []
    created: set[tuple[str, str]] = set()
    deleted: set[tuple[str, str]] = set()
    for line in lines:
        op = _parse_line(line, before)
        if (op.config, op.section) in deleted:
            # The section is gone: the router takes no change of it, and
            # the two changes belong in two changes, one after the
            # other.
            raise OwnerScriptError(
                f"the batch deletes {op.config}.{op.section} and then "
                "changes it; split it into two changes"
            )
        if op.option is not None:
            known = _entry(before, op.config, op.section)
            if known is None and (op.config, op.section) not in created:
                raise OwnerScriptError(
                    f"the section {op.config}.{op.section} does not exist on the router"
                )
        if op.verb == "set" and op.option is None:
            created.add((op.config, op.section))
        if op.verb == "delete" and op.option is None:
            deleted.add((op.config, op.section))
        ops.append(op)
    if len(ops) > MAX_OPS:
        raise OwnerScriptError(
            f"an owner script may carry at most {MAX_OPS} changes"
        )
    _check_policy(ops, before, device, uci_batch)
    # the preconditions hold the router's own values, so they are built
    # here: a router value that cannot be written into a check refuses
    # the script before anything is written.
    preconditions(ops, before)
    return ops


def _check_policy(
    ops: Sequence[OwnerOp], before: Any, device: Any, uci_batch: str
) -> None:
    """The policy's verdict on the change, and the refusal of the bad ones."""
    facts: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    for config, sections in getattr(before, "configs", {}).items():
        if not isinstance(sections, Mapping):
            continue
        for name, entry in sections.items():
            if not isinstance(entry, Mapping):
                continue
            section_type = entry.get(".type")
            # The router's own "section <cfg> <sec> <type> <name>" seal
            # line carries the section's name OPTION, not its uci name:
            # the policy reads it to know which zone a section is.
            section_name = entry.get("name")
            facts[(config, name)] = (
                section_type if isinstance(section_type, str) else None,
                section_name if isinstance(section_name, str) else None,
            )
    diff = render_diff(ops, before)
    try:
        decision = policy.classify(device, uci_batch, diff, facts)
    except ValueError as exc:
        raise OwnerScriptError(f"the change cannot be judged: {exc}") from None
    for reason in decision.get("reasons", []):
        code = _reason_code(str(reason))
        if code in REFUSED_REASONS:
            raise OwnerScriptError(
                f"the policy refuses this change ({code}): {_unit_list(ops)}"
            )


# ---- the diff --------------------------------------------------------------


def render_diff(ops: Sequence[OwnerOp], before: Any) -> str:
    """The text ``uci changes`` would print for these ops.

    The policy reads the diff and the owner reads it, so it is the
    shape uci prints: a new section as ``config.name=type``, a value as
    ``config.name.option='value'``, a list item with the ``+`` or ``-``
    marker on the option and a deletion as a leading ``-``.
    """
    lines: list[str] = []
    for op in ops:
        key = op_key(op)
        if op.verb == "set":
            if op.option is None:
                lines.append(f"{key}={op.type}")
            else:
                lines.append(f"{key}='{op.value}'")
        elif op.verb == "add_list":
            lines.append(f"{key}+='{op.value}'")
        elif op.verb == "del_list":
            lines.append(f"{key}-='{op.value}'")
        elif op.verb == "delete":
            lines.append(f"-{key}")
        elif op.verb == "reorder":
            lines.append(f"^{key}={op.value}")
    return "\n".join(lines)


# ---- the expected values ---------------------------------------------------


def running_values(
    ops: Sequence[OwnerOp], before: Any
) -> dict[Unit, str | tuple[str, ...] | None]:
    """What every touched unit holds once the ops have run, in order.

    The ops run in order, so every op works on the RUNNING state: what
    the op before it left.  A batch that adds to a list twice holds
    both items, and a batch that takes an item from a list and then adds
    one holds the list the two ops made, not the list the backup holds.

    ``None`` is a proven absence: the option is not there any more.
    A list option is a tuple of its items, in order.
    """
    running: dict[Unit, str | tuple[str, ...] | None] = {}
    for op in ops:
        unit: Unit = (op.config, op.section, op.option)
        if op.verb == "set" and op.option is None:
            running[unit] = op.type
            continue
        if op.verb == "delete" and op.option is None:
            # The whole section goes away.  The section itself is a
            # proven absence; its options are not units any more: a
            # section that is not there holds no options, so there is
            # nothing the router could answer for them.
            running[unit] = None
            for key in [
                key
                for key in running
                if key[0] == op.config
                and key[1] == op.section
                and key[2] is not None
            ]:
                del running[key]
            continue
        if unit in running:
            current = running[unit]
        else:
            current = _current(before, op.config, op.section, op.option or "")
        if op.verb == "set":
            value: str | tuple[str, ...] | None = op.value
        elif op.verb == "delete":
            value = None
        elif op.verb == "add_list":
            if current is None:
                value = (op.value or "",)
            elif isinstance(current, tuple):
                value = current + (op.value or "",)
            else:
                value = (current, op.value or "")
        elif op.verb == "del_list":
            if current is None:
                value = None
            elif isinstance(current, tuple):
                # uci's del_list takes EVERY item that is equal to the
                # value (measured), and a list that has no item left is
                # not a list any more: the option is gone.
                remaining = [
                    item for item in current if item != (op.value or "")
                ]
                value = tuple(remaining) if remaining else None
            else:
                value = current
        else:
            value = current
        running[unit] = value
    return running


def expected_after(
    ops: Sequence[OwnerOp], before: Any
) -> dict[Unit, str | tuple[str, ...] | None]:
    """What every touched unit holds once the change is applied."""
    return running_values(ops, before)


def _same_value(left: Any, right: Any) -> bool:
    """True when two unit values are the same.

    A list is a list: it compares as a list, in order.  A value and an
    absence are never the same.
    """
    if isinstance(left, tuple) or isinstance(right, tuple):
        if not isinstance(left, tuple) or not isinstance(right, tuple):
            return False
        return list(left) == list(right)
    return left == right


def changes_nothing(ops: Sequence[OwnerOp], before: Any) -> bool:
    """True when the ops leave every unit they touch as it was.

    A change that stages nothing is a change that does nothing: uci
    would have nothing to apply, and the script would stop on the
    router with "nothing to apply".  Newton says so at plan time, in
    its own words.
    """
    expected = expected_after(ops, before)
    for unit in touched_units(ops, before):
        config, section, option = unit
        if option is None:
            current: Any = _section_type(before, config, section)
        else:
            current = _current(before, config, section, option)
        want = expected.get(unit)
        if want is None and unit not in expected:
            # the unit is not an expected value at all (an option of a
            # deleted section): the change takes it away with the
            # section, so it is never "nothing"
            return False
        if not _same_value(current, want):
            return False
    return True


def after_configs(
    before: Any, ops: Sequence[OwnerOp]
) -> dict[str, dict[str, dict[str, Any]]]:
    """The configs as they hold once the ops have run.

    This is the backup of the state a restore script runs against: the
    same running state the expected values are built from, so the two
    always agree.
    """
    configs: dict[str, dict[str, dict[str, Any]]] = {}
    for config, sections in getattr(before, "configs", {}).items():
        if not isinstance(sections, Mapping):
            continue
        configs[str(config)] = {
            str(name): {str(key): value for key, value in entry.items()}
            for name, entry in sections.items()
            if isinstance(entry, Mapping)
        }
    for unit, value in running_values(ops, before).items():
        config, section, option = unit
        sections = configs.setdefault(config, {})
        if option is None:
            if value is None:
                sections.pop(section, None)
                continue
            entry = sections.setdefault(section, {})
            entry[".type"] = value
            entry.setdefault(".name", section)
            entry.setdefault(".anonymous", False)
            continue
        entry = sections.get(section)
        if not isinstance(entry, Mapping):
            continue
        if value is None:
            entry.pop(option, None)
        elif isinstance(value, tuple):
            entry[option] = list(value)
        else:
            entry[option] = value
    return configs


def touched_units(ops: Sequence[OwnerOp], before: Any) -> set[Unit]:
    """Every unit the change touches.

    That is every unit the ops name, and every option of every section
    the change deletes: the change takes the whole section away, so the
    options of that section change too.  Their EXPECTED values are not
    in ``expected_after``: a section that is gone holds no options, and
    the router cannot answer for them.
    """
    units: set[Unit] = set()
    for op in ops:
        units.add((op.config, op.section, op.option))
    for op in ops:
        if op.verb != "delete" or op.option is not None:
            continue
        entry = _entry(before, op.config, op.section) or {}
        for name in entry:
            if name.startswith("."):
                continue
            units.add((op.config, op.section, name))
    return units


# ---- the preconditions -----------------------------------------------------


def preconditions(
    ops: Sequence[OwnerOp], before: Any
) -> tuple[tuple[str, str | None], ...]:
    """The checks the script makes before it stages anything.

    Each pair is the key and the value the router must hold; a value of
    None means the router must not have it at all.  The key of a whole
    section names its type.
    """
    units = touched_units(ops, before)
    created = {
        (op.config, op.section)
        for op in ops
        if op.verb == "set"
        and op.option is None
        and _entry(before, op.config, op.section) is None
    }
    checks: list[tuple[str, str | None]] = []
    for unit in sorted(units, key=lambda item: (item[0], item[1], item[2] or "")):
        config, section, option = unit
        if option is None:
            if (config, section) in created:
                checks.append((f"{config}.{section}", None))
            else:
                section_type = _section_type(before, config, section)
                if section_type is None:
                    raise OwnerScriptError(
                        UNSAFE_CHECK_REFUSAL.format(unit=f"{config}.{section}")
                    )
                checks.append((f"{config}.{section}", section_type))
            continue
        if (config, section) in created:
            # the section itself must not be there: its options cannot be
            continue
        current = _current(before, config, section, option)
        if current is None:
            checks.append((f"{config}.{section}.{option}", None))
            continue
        if isinstance(current, tuple):
            joined = " ".join(current)
            if not check_value(joined) or any(" " in item for item in current):
                raise OwnerScriptError(
                    UNSAFE_CHECK_REFUSAL.format(unit=f"{config}.{section}.{option}")
                )
            checks.append((f"{config}.{section}.{option}", joined))
        else:
            if not check_value(current):
                raise OwnerScriptError(
                    UNSAFE_CHECK_REFUSAL.format(unit=f"{config}.{section}.{option}")
                )
            checks.append((f"{config}.{section}.{option}", current))
    return tuple(checks)


# ---- the inverse -----------------------------------------------------------


def _restore_value_ops(
    config: str, section: str, option: str, old: Any
) -> list[OwnerOp]:
    """The ops that put one option back the way it was."""
    if old is None:
        return [OwnerOp("delete", config, section, option, None, None)]
    if isinstance(old, tuple):
        ops = [OwnerOp("delete", config, section, option, None, None)]
        for item in old:
            ops.append(OwnerOp("add_list", config, section, option, item, None))
        return ops
    return [OwnerOp("set", config, section, option, old, None)]


def inverse_ops(ops: Sequence[OwnerOp], before: Any) -> list[OwnerOp]:
    """The ops that undo the change, in the order they must run.

    Every touched option goes back to the value the backup holds, an
    option that did not exist is deleted, a list is rebuilt with a
    delete and one add per item, and a section that was added is
    deleted.  A section that was deleted is re-created under a new name
    and moved back to its old place: the router does not let a script
    put a deleted section back under its old name, so the verdict says
    so.

    A unit the batch touched more than once is restored ONCE, from the
    backup: the backup holds what the router held before the change, so
    one restore of that value undoes every op on the unit.
    """
    order: list[Unit] = []
    groups: dict[Unit, list[OwnerOp]] = {}
    for op in ops:
        unit: Unit = (op.config, op.section, op.option)
        if unit not in groups:
            groups[unit] = []
            order.append(unit)
        groups[unit].append(op)
    expected = expected_after(ops, before)
    deleted = {
        (op.config, op.section)
        for op in ops
        if op.verb == "delete" and op.option is None
    }
    inverse: list[OwnerOp] = []
    for unit in reversed(order):
        config, section, option = unit
        if option is not None and (config, section) in deleted:
            # The restore re-creates the deleted section with the
            # values the backup holds, under a new name.  A restore op
            # on the section itself would be refused by uci: the
            # section is not there any more.
            continue
        inverse.extend(_restore_unit(unit, groups[unit], before, expected))
    return inverse


def _restore_unit(
    unit: Unit,
    group: Sequence[OwnerOp],
    before: Any,
    expected: Mapping[Unit, Any],
) -> list[OwnerOp]:
    """The ops that put one touched unit back the way the backup holds it."""
    config, section, option = unit
    if option is None:
        deleted = [op for op in group if op.verb == "delete"]
        if deleted:
            return _restore_section(before, deleted[0])
        if _entry(before, config, section) is None:
            # the change added the section: the restore takes it away
            return [OwnerOp("delete", config, section, None, None, None)]
        return []
    old = _current(before, config, section, option)
    final = expected.get(unit)
    if old is None and final is None:
        # the option was not there and is not there: nothing to restore
        return []
    if isinstance(old, tuple) and (final is None or final == ()):
        # the change took the option away (a delete, or a list it
        # emptied): the items go back, and the option comes back with
        # them.  A delete of an option that is not there is refused by
        # uci, so the restore must not carry one.
        return [
            OwnerOp("add_list", config, section, option, item, None) for item in old
        ]
    return _restore_value_ops(config, section, option, old)


def _restore_section(before: Any, op: OwnerOp) -> list[OwnerOp]:
    """The ops that re-create a section the change deleted."""
    entry = _entry(before, op.config, op.section)
    if entry is None:
        return []
    section_type = entry.get(".type")
    if not isinstance(section_type, str) or not section_type:
        return []
    index = _section_index(before, op.config, op.section)
    sid = str(getattr(before, "sid", "") or "")
    stem = sid[:8] if sid else "00000000"
    name = f"{RESTORE_NAME_PREFIX}{stem}_{index if index is not None else 0}"
    if not ADDED_NAME_RE.fullmatch(name):
        name = f"{RESTORE_NAME_PREFIX}{stem}_0"
    ops = [OwnerOp("set", op.config, name, None, None, section_type)]
    for key, value in entry.items():
        if key.startswith("."):
            continue
        if isinstance(value, (list, tuple)):
            for item in value:
                ops.append(
                    OwnerOp("add_list", op.config, name, key, str(item), None)
                )
        else:
            ops.append(
                OwnerOp("set", op.config, name, key, str(value), None)
            )
    if index is not None:
        ops.append(OwnerOp("reorder", op.config, name, None, str(index), None))
    return ops
