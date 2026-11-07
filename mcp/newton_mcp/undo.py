"""Undo after confirm: the pure core that turns a config back into its backup.

Newton can undo a confirmed change on an OpenWrt router.  It holds the
router's config from before the change (B, a backup tarball of /etc/config)
and the config now (C, a fresh backup tarball); the caller guarantees that C
is exactly the state right after the change.  This module turns "C -> B" into
a ``uci batch`` for ONE package at a time: the sections, their order and
their options included.

Every batch this module builds is proved before it is handed over: the batch
is simulated on C and the result must equal B, or the module refuses
(``UndoError``).  A refusal may name a package, a section or an option; it
never names a config value, because a config value can be a secret.

Nothing here talks to a router: no shell, no subprocess, standard library
only.
"""

from __future__ import annotations

import difflib
import hashlib
import re
import shlex
import tarfile
from dataclasses import dataclass
from pathlib import Path


class UndoError(ValueError):
    """Refusal. The message is safe to show an agent: it may name a package,
    section or option, NEVER a config value."""


@dataclass(frozen=True)
class Section:
    """One section of a uci config file."""

    type: str
    name: str | None
    options: tuple[tuple[str, str | tuple[str, ...]], ...]


_NAME_RE = re.compile(r"[A-Za-z0-9_.-]+")
_MEMBER_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")
_ADDRESS_RE = re.compile(r"@([A-Za-z0-9_.-]+)\[(-?\d+)\]")
_MAX_BATCH_WORDS = 4


# --------------------------------------------------------------- parsing


class _WordError(Exception):
    """A line cannot be split into words."""


class _Draft:
    """A section while it is being parsed."""

    __slots__ = ("type", "name", "options")

    def __init__(self, stype: str, name: str | None) -> None:
        self.type = stype
        self.name = name
        self.options: list[tuple[str, str | tuple[str, ...]]] = []


def _is_name(text: str) -> bool:
    """True for a name uci accepts."""
    return bool(text) and _NAME_RE.fullmatch(text) is not None


def _is_safe(text: str) -> bool:
    """True for text that can be written inside a batch line as 'text'."""
    return all(0x20 <= ord(char) <= 0x7E and char not in "'\"\\" for char in text)


def _read_double_quoted(line: str, start: int) -> tuple[str, int]:
    """Read a double quoted string; only \\" and \\\\ are escapes."""
    out: list[str] = []
    index = start + 1
    while index < len(line):
        char = line[index]
        if char == '"':
            return "".join(out), index + 1
        if char == "\\":
            following = line[index + 1] if index + 1 < len(line) else ""
            if following in ('"', "\\"):
                out.append(following)
                index += 2
                continue
            out.append("\\")
            index += 1
            continue
        out.append(char)
        index += 1
    raise _WordError("unterminated quote")


def _split_words(line: str) -> list[str]:
    """Split a uci line into shell-like words.

    Unquoted words, 'single quoted' words (literal) and "double quoted"
    words (with \\" and \\\\ as escapes) sit next to each other and join into
    one word, so 'it'\\''s' is it's.
    """
    words: list[str] = []
    parts: list[str] = []
    index = 0
    length = len(line)
    while index < length:
        char = line[index]
        if char in " \t":
            if parts:
                words.append("".join(parts))
                parts = []
            index += 1
        elif char == "'":
            end = line.find("'", index + 1)
            if end < 0:
                raise _WordError("unterminated quote")
            parts.append(line[index + 1 : end])
            index = end + 1
        elif char == '"':
            text, index = _read_double_quoted(line, index)
            parts.append(text)
        elif char == "\\":
            # only the exporter's own form for a quote, \\', is read; libuci's other readings
            # of a backslash outside quotes are not modelled, so they are refused
            if index + 1 < length and line[index + 1] == "'":
                parts.append("'")
                index += 2
            else:
                raise _WordError("backslash outside quotes")
        else:
            end = index
            while end < length and line[end] not in " \t'\"\\":
                end += 1
            if "#" in line[index:end]:
                # a comment character inside a word: libuci's reading is not modelled
                raise _WordError("comment character outside quotes")
            parts.append(line[index:end])
            index = end
    if parts:
        words.append("".join(parts))
    return words


def _set_option(options: list[tuple[str, str | tuple[str, ...]]], name: str, value: str) -> None:
    """An option set again: the last value wins, the first place is kept."""
    for position, (option, _) in enumerate(options):
        if option == name:
            options[position] = (name, value)
            return
    options.append((name, value))


def _add_list(options: list[tuple[str, str | tuple[str, ...]]], name: str, value: str) -> None:
    """A list value: the values collect in order at the place of the first one."""
    for position, (option, current) in enumerate(options):
        if option == name:
            if isinstance(current, tuple):
                options[position] = (name, current + (value,))
            else:
                options[position] = (name, (current, value))
            return
    options.append((name, (value,)))


def _parse_config_line(drafts: list[_Draft], lineno: int, words: list[str]) -> None:
    if len(words) < 2:
        raise UndoError(f"line {lineno}: config needs a type")
    if len(words) > 3:
        raise UndoError(f"line {lineno}: trailing junk after the section name")
    stype = words[1]
    if not _is_name(stype):
        raise UndoError(f"line {lineno}: invalid section type")
    name = None
    if len(words) == 3:
        if words[2] == "":
            raise UndoError(f"line {lineno}: empty section name")
        if not _is_name(words[2]):
            raise UndoError(f"line {lineno}: invalid section name")
        name = words[2]
    drafts.append(_Draft(stype, name))


def _parse_option_line(
    drafts: list[_Draft], lineno: int, words: list[str], keyword: str
) -> None:
    if not drafts:
        raise UndoError(f"line {lineno}: {keyword} before any config section")
    if len(words) < 3:
        raise UndoError(f"line {lineno}: {keyword} needs a name and a value")
    if len(words) > 3:
        raise UndoError(f"line {lineno}: trailing junk after the value")
    name = words[1]
    if not _is_name(name):
        raise UndoError(f"line {lineno}: invalid option name")
    value = words[2]
    for existing, current in drafts[-1].options:
        if existing == name and isinstance(current, tuple) != (keyword == "list"):
            raise UndoError(f"line {lineno}: {name} is both an option and a list")
    if keyword == "option":
        _set_option(drafts[-1].options, name, value)
    else:
        _add_list(drafts[-1].options, name, value)


def parse_uci_config(text: str) -> list[Section]:
    """Read the text of one /etc/config/<pkg> file into its sections.

    A section with a name is named; a section without one is anonymous.  A
    section name that looks like a uci generated id (cfg and six hex
    characters) is still a named section here.  Options that are set twice
    keep the first place and the last value; list values collect in order.

    The grammar is strict: a line is a comment, a package line, a config
    line, an option line or a list line, and an option or list always has a
    value.  A line uci would read as an option without a value, or a bare
    'name value' line, is refused rather than guessed at.
    """
    drafts: list[_Draft] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            words = _split_words(line)
        except _WordError as exc:
            raise UndoError(f"line {lineno}: {exc}") from None
        if not words:
            continue
        keyword = words[0]
        if keyword == "package":
            if len(words) != 2:
                raise UndoError(f"line {lineno}: package needs a name")
            continue
        if keyword == "config":
            _parse_config_line(drafts, lineno, words)
            continue
        if keyword in ("option", "list"):
            _parse_option_line(drafts, lineno, words, keyword)
            continue
        raise UndoError(f"line {lineno}: unknown keyword")
    return [Section(draft.type, draft.name, tuple(draft.options)) for draft in drafts]


# ------------------------------------------------------------ the batch


def _batch_words(line: str) -> list[str]:
    """The words of one batch line."""
    try:
        words = shlex.split(line, posix=True)
    except ValueError:
        raise UndoError("batch line cannot be read") from None
    if not words:
        raise UndoError("batch line is empty")
    if len(words) > _MAX_BATCH_WORDS:
        raise UndoError("batch line has too many words")
    return words


def _package_mismatch(name: str, package: str) -> UndoError:
    """The refusal for a batch line that names another package.

    The name comes from the line, so it is only shown when it is plain
    printable text.
    """
    if not _is_safe(name) or not _is_safe(package):
        return UndoError("batch line names another package")
    return UndoError(f"batch line names package {name}, not {package}")


def _split_package(argument: str, package: str) -> str:
    """Take the package off an argument and check it is the package we work on."""
    if "." not in argument:
        raise UndoError("batch argument has no section")
    name, rest = argument.split(".", 1)
    if name != package:
        raise _package_mismatch(name, package)
    return rest


def _split_target(rest: str) -> tuple[str, str | None, str]:
    """Split 'SEC.OPT=VALUE' or 'SEC=VALUE' into the section, the option and the value.

    The section may hold a dot in its name, so the option (when there is one)
    is what follows the first dot of the rest.
    """
    if "=" not in rest:
        raise UndoError("batch argument needs a value")
    left, value = rest.split("=", 1)
    if "." in left:
        section, option = left.split(".", 1)
        return section, option, value
    return left, None, value


def _resolve_section(state: list[Section], address: str) -> int:
    """The place of the section an address names."""
    if address.startswith("@"):
        return _resolve_anonymous(state, address)
    if not _is_name(address):
        raise UndoError("invalid section name")
    for position, section in enumerate(state):
        if section.name == address:
            return position
    raise UndoError("unknown section")


def _resolve_anonymous(state: list[Section], address: str) -> int:
    """The place of the section an '@TYPE[K]' address names."""
    found = _ADDRESS_RE.fullmatch(address)
    if found is None:
        raise UndoError("invalid section address")
    stype = found.group(1)
    index = int(found.group(2))
    matches = [position for position, section in enumerate(state) if section.type == stype]
    if not matches:
        raise UndoError("unknown section address")
    real = index if index >= 0 else len(matches) + index
    if not 0 <= real < len(matches):
        raise UndoError("section address out of range")
    return matches[real]


def _replace_section(state: list[Section], position: int, section: Section) -> list[Section]:
    new = list(state)
    new[position] = section
    return new


def _apply_add(state: list[Section], words: list[str]) -> list[Section]:
    stype = words[2]
    if not _is_name(stype):
        raise UndoError("invalid section type")
    return [*state, Section(stype, None, ())]


def _apply_set(state: list[Section], rest: str) -> list[Section]:
    section, option, value = _split_target(rest)
    if option is None:
        if not _is_name(section):
            raise UndoError("invalid section name")
        if not _is_name(value):
            raise UndoError("invalid section type")
        for position, existing in enumerate(state):
            if existing.name == section:
                return _replace_section(
                    state, position, Section(value, existing.name, existing.options)
                )
        return [*state, Section(value, section, ())]
    position = _resolve_section(state, section)
    if not _is_name(option):
        raise UndoError("invalid option name")
    if value == "":
        raise UndoError("uci does not set an empty value")
    existing = state[position]
    options = list(existing.options)
    for slot, (name, _) in enumerate(options):
        if name == option:
            options[slot] = (option, value)
            break
    else:
        options.append((option, value))
    return _replace_section(
        state, position, Section(existing.type, existing.name, tuple(options))
    )


def _apply_add_list(state: list[Section], rest: str) -> list[Section]:
    section, option, value = _split_target(rest)
    if option is None:
        raise UndoError("add_list needs an option")
    position = _resolve_section(state, section)
    if not _is_name(option):
        raise UndoError("invalid option name")
    if value == "":
        raise UndoError("uci does not add an empty list value")
    existing = state[position]
    options = list(existing.options)
    for slot, (name, current) in enumerate(options):
        if name == option:
            if not isinstance(current, tuple):
                raise UndoError("option is not a list")
            options[slot] = (option, current + (value,))
            break
    else:
        options.append((option, (value,)))
    return _replace_section(
        state, position, Section(existing.type, existing.name, tuple(options))
    )


def _apply_del_list(state: list[Section], rest: str) -> list[Section]:
    section, option, value = _split_target(rest)
    if option is None:
        raise UndoError("del_list needs an option")
    position = _resolve_section(state, section)
    if not _is_name(option):
        raise UndoError("invalid option name")
    existing = state[position]
    options = list(existing.options)
    for slot, (name, current) in enumerate(options):
        if name == option:
            if not isinstance(current, tuple):
                raise UndoError("option is not a list")
            remaining = tuple(item for item in current if item != value)
            if len(remaining) == len(current):
                raise UndoError("value is not in the list")
            if remaining:
                options[slot] = (option, remaining)
            else:
                del options[slot]
            return _replace_section(
                state, position, Section(existing.type, existing.name, tuple(options))
            )
    raise UndoError("unknown option")


def _apply_delete(state: list[Section], rest: str) -> list[Section]:
    if "." in rest:
        section, option = rest.split(".", 1)
        if not _is_name(option):
            raise UndoError("invalid option name")
        position = _resolve_section(state, section)
        existing = state[position]
        options = [(name, value) for name, value in existing.options if name != option]
        if len(options) == len(existing.options):
            raise UndoError("unknown option")
        return _replace_section(
            state, position, Section(existing.type, existing.name, tuple(options))
        )
    position = _resolve_section(state, rest)
    new = list(state)
    del new[position]
    return new


def _apply_reorder(state: list[Section], rest: str) -> list[Section]:
    section, option, value = _split_target(rest)
    if option is not None:
        raise UndoError("reorder needs a section")
    position = _resolve_section(state, section)
    try:
        target = int(value)
    except ValueError:
        raise UndoError("reorder needs a place") from None
    if not 0 <= target < len(state):
        raise UndoError("reorder place out of range")
    new = list(state)
    moved = new.pop(position)
    new.insert(target, moved)
    return new


def _apply_words(package: str, state: list[Section], words: list[str]) -> list[Section]:
    """Run one batch line on a package state; the input is never changed."""
    verb = words[0]
    if verb == "add":
        if len(words) != 3:
            raise UndoError("add needs a package and a type")
        if words[1] != package:
            raise _package_mismatch(words[1], package)
        return _apply_add(state, words)
    if verb in ("set", "add_list", "del_list", "delete", "reorder"):
        if len(words) != 2:
            raise UndoError(f"{verb} needs one argument")
        rest = _split_package(words[1], package)
        if verb == "set":
            return _apply_set(state, rest)
        if verb == "add_list":
            return _apply_add_list(state, rest)
        if verb == "del_list":
            return _apply_del_list(state, rest)
        if verb == "delete":
            return _apply_delete(state, rest)
        return _apply_reorder(state, rest)
    raise UndoError("unknown batch verb")


def apply_batch(package: str, sections: list[Section], lines: list[str]) -> list[Section]:
    """Apply a uci batch to one package state (the reference simulator).

    The verbs are add, set, add_list, del_list, delete and reorder.  A
    section is named by its name or by '@TYPE[K]', where K counts the
    sections of that type in the state and a negative K counts from the end.
    """
    state = list(sections)
    for line in lines:
        state = _apply_words(package, state, _batch_words(line))
    return state


# --------------------------------------------------------- the inverse


def _same_option(one: str | tuple[str, ...], other: str | tuple[str, ...]) -> bool:
    if isinstance(one, tuple) != isinstance(other, tuple):
        return False
    if isinstance(one, tuple) and isinstance(other, tuple):
        return tuple(one) == tuple(other)
    return one == other


def _same_section(one: Section, other: Section) -> bool:
    """Same section; the order of the options inside it does not count."""
    if one.type != other.type or one.name != other.name:
        return False
    first = dict(one.options)
    second = dict(other.options)
    if first.keys() != second.keys():
        return False
    return all(_same_option(first[key], second[key]) for key in first)


def _same_state(one: list[Section], other: list[Section]) -> bool:
    if len(one) != len(other):
        return False
    return all(_same_section(left, right) for left, right in zip(one, other))


def _align(
    current: list[Section], target: list[Section]
) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    """Match the sections of the current state with the sections of the target.

    A named section matches the section with the same name and the same type;
    a named section whose name is there with another type is deleted and added
    again.  Anonymous sections are matched with difflib over their type and
    their options; inside a block that does not match, the sections of one
    type are paired in order and the rest are deleted and added.
    """
    matches: list[tuple[int, int]] = []
    cur_only: list[int] = []
    tgt_only: list[int] = []
    target_named = {
        section.name: index for index, section in enumerate(target) if section.name is not None
    }
    matched_target: set[int] = set()
    cur_anon: list[int] = []
    tgt_anon: list[int] = []
    for index, section in enumerate(current):
        if section.name is None:
            cur_anon.append(index)
            continue
        other = target_named.get(section.name)
        if other is None:
            cur_only.append(index)
        elif target[other].type != section.type:
            cur_only.append(index)
            tgt_only.append(other)
            matched_target.add(other)
        else:
            matches.append((index, other))
            matched_target.add(other)
    for index, section in enumerate(target):
        if section.name is None:
            tgt_anon.append(index)
        elif index not in matched_target:
            tgt_only.append(index)
    matcher = difflib.SequenceMatcher(
        a=[(current[index].type, current[index].options) for index in cur_anon],
        b=[(target[index].type, target[index].options) for index in tgt_anon],
        autojunk=False,
    )
    for tag, first, last, other_first, other_last in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(last - first):
                matches.append((cur_anon[first + offset], tgt_anon[other_first + offset]))
        elif tag == "replace":
            pool: dict[str, list[int]] = {}
            for other in range(other_first, other_last):
                pool.setdefault(target[tgt_anon[other]].type, []).append(tgt_anon[other])
            taken: set[int] = set()
            for index in range(first, last):
                stype = current[cur_anon[index]].type
                choices = pool.get(stype, [])
                free = [other for other in choices if other not in taken]
                if free:
                    taken.add(free[0])
                    matches.append((cur_anon[index], free[0]))
                else:
                    cur_only.append(cur_anon[index])
            for other in range(other_first, other_last):
                if tgt_anon[other] not in taken:
                    tgt_only.append(tgt_anon[other])
        elif tag == "delete":
            cur_only.extend(cur_anon[index] for index in range(first, last))
        else:
            tgt_only.extend(tgt_anon[index] for index in range(other_first, other_last))
    return matches, cur_only, tgt_only


def _type_index(state: list[Section], position: int) -> int:
    """How many sections of the same type come before this place."""
    stype = state[position].type
    return sum(1 for section in state[:position] if section.type == stype)


def _address_at(state: list[Section], position: int) -> str:
    """How this section is named in a batch line."""
    section = state[position]
    if section.name is not None:
        return section.name
    return f"@{section.type}[{_type_index(state, position)}]"


def _check_addressable(package: str, section: Section) -> None:
    """A section can only be named in a batch line when its name has no dot in it."""
    if section.name is not None:
        if not _is_safe(section.name):
            raise UndoError(f"{package} has a section name that cannot be written safely")
        if not _is_name(section.name):
            raise UndoError(f"{package}.{section.name} has an invalid section name")
        if "." in section.name:
            raise UndoError(f"{package}.{section.name} cannot be addressed safely")
        if not _is_safe(section.type):
            raise UndoError(f"{package}.{section.name} has a type that cannot be written safely")
        if not _is_name(section.type):
            raise UndoError(f"{package}.{section.name} has an invalid section type")
        return
    if not _is_safe(section.type):
        raise UndoError(f"{package} has a section type that cannot be written safely")
    if not _is_name(section.type):
        raise UndoError(f"{package}.@{section.type} has an invalid section type")
    if "." in section.type:
        raise UndoError(f"{package}.@{section.type} cannot be addressed safely")


def _write_value(path: str, value: str) -> str:
    """The quoted value for a batch line, or a refusal when it cannot be written."""
    if value == "":
        # measured on OpenWrt 25.12.5: uci set with '' creates nothing and deletes an existing option
        raise UndoError(f"{path} has an empty value that uci cannot restore")
    if not _is_safe(value):
        raise UndoError(f"{path} has a value that cannot be written safely")
    return f"'{value}'"


def _check_option(path: str, name: str) -> None:
    """The option name must be one uci accepts and one that can be written."""
    if not _is_safe(name):
        raise UndoError(f"{path} has a value that cannot be written safely")
    if not _is_name(name):
        raise UndoError(f"{path} has an invalid option name")


def _option_fix_lines(
    package: str, address: str, current: Section, target: Section
) -> list[str]:
    """The lines that turn the options of one section into the target's."""
    lines: list[str] = []
    have = dict(current.options)
    want = dict(target.options)
    for name, _ in current.options:
        if name in want:
            continue
        path = f"{package}.{address}.{name}"
        _check_option(path, name)
        lines.append(f"delete {package}.{address}.{name}")
    for name, value in target.options:
        if name in have and _same_option(have[name], value):
            continue
        path = f"{package}.{address}.{name}"
        _check_option(path, name)
        if isinstance(value, tuple):
            if name in have:
                lines.append(f"delete {package}.{address}.{name}")
            for item in value:
                lines.append(
                    f"add_list {package}.{address}.{name}={_write_value(path, item)}"
                )
        else:
            if name in have and isinstance(have[name], tuple):
                lines.append(f"delete {package}.{address}.{name}")
            lines.append(
                f"set {package}.{address}.{name}={_write_value(path, value)}"
            )
    return lines


def _new_section_lines(package: str, target: Section) -> list[str]:
    """The lines that make a section that is not in the current state."""
    lines: list[str] = []
    if target.name is not None:
        address = target.name
        _check_addressable(package, target)
        lines.append(f"set {package}.{address}={target.type}")
    else:
        address = f"@{target.type}[-1]"
        _check_addressable(package, target)
        lines.append(f"add {package} {target.type}")
    for name, value in target.options:
        path = f"{package}.{address}.{name}"
        _check_option(path, name)
        if isinstance(value, tuple):
            for item in value:
                lines.append(
                    f"add_list {package}.{address}.{name}={_write_value(path, item)}"
                )
        else:
            lines.append(
                f"set {package}.{address}.{name}={_write_value(path, value)}"
            )
    return lines


def inverse_batch(package: str, current: list[Section], target: list[Section]) -> list[str]:
    """The uci batch that turns `current` into `target`, one package at a time.

    The batch uses only the verbs add, set, add_list, del_list, delete and
    reorder.  The batch is simulated on `current` before it is returned; when
    the simulation does not give `target` back, the module refuses instead of
    handing over a batch that would not undo the change.
    """
    if _same_state(current, target):
        return []
    if not _is_name(package):
        raise UndoError(f"{package} is not a package name")
    for section in [*current, *target]:
        _check_addressable(package, section)
    matches, cur_only, tgt_only = _align(current, target)
    state = list(current)
    origins = list(range(len(current)))
    wanted: list[int | None] = [None] * len(current)
    for here, there in matches:
        wanted[here] = there
    lines: list[str] = []

    # 1. the options of the sections that stay, before anything is removed
    for here, there in sorted(matches):
        address = _address_at(state, here)
        for line in _option_fix_lines(package, address, current[here], target[there]):
            state = _apply_words(package, state, _batch_words(line))
            lines.append(line)

    # 2. the sections that are gone, the highest place of their type first
    for here in sorted(cur_only, key=lambda index: (-_type_index(current, index), index)):
        position = origins.index(here)
        address = _address_at(state, position)
        line = f"delete {package}.{address}"
        # the line takes the section out of the state itself
        state = _apply_words(package, state, _batch_words(line))
        del origins[position]
        del wanted[position]
        lines.append(line)

    # 3. the sections that are new
    for there in tgt_only:
        for line in _new_section_lines(package, target[there]):
            state = _apply_words(package, state, _batch_words(line))
            lines.append(line)
        origins.append(None)
        wanted.append(there)

    # 4. the order of the sections
    for index in range(len(target)):
        if len(state) != len(target):
            break
        if wanted[index] == index:
            continue
        if index not in wanted:
            break
        position = wanted.index(index)
        address = _address_at(state, position)
        line = f"reorder {package}.{address}={index}"
        state = _apply_words(package, state, _batch_words(line))
        origins.insert(index, origins.pop(position))
        wanted.insert(index, wanted.pop(position))
        lines.append(line)

    # 5. the proof: the batch has to give the target back
    result = apply_batch(package, current, lines)
    if not _same_state(result, target):
        raise UndoError(f"cannot build a safe inverse for package {package}")
    return lines


# ------------------------------------------------------------ the backup


def _member_config_name(member_name: str) -> str | None:
    """The config name of a tar member, or None when it is not a config file."""
    path = member_name
    while path.startswith("./"):
        path = path[2:]
    prefix = "etc/config/"
    if not path.startswith(prefix):
        return None
    name = path[len(prefix) :]
    if _MEMBER_NAME_RE.fullmatch(name) is None:
        return None
    return name


def read_config_members(
    tar_path: Path, wanted: set[str], max_member_bytes: int = 1_048_576
) -> dict[str, bytes | None]:
    """Read the wanted /etc/config files out of a backup tarball.

    The tarball is read in memory and never extracted.  Only the members
    named exactly etc/config/<name> that are regular files are read; a
    symlink, a hard link, a device or a directory is ignored and never
    followed.  A member that is not there is None.
    """
    for name in wanted:
        if _MEMBER_NAME_RE.fullmatch(name) is None:
            raise ValueError(f"config name is not usable: {name!r}")
    result: dict[str, bytes | None] = {name: None for name in wanted}
    if not result:
        return result
    try:
        with tarfile.open(tar_path, mode="r:gz") as archive:
            for member in archive:
                name = _member_config_name(member.name)
                if name is None or name not in result:
                    continue
                if not member.isfile():
                    continue
                if member.size > max_member_bytes:
                    raise UndoError(f"config {name} is too large")
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                data = handle.read()
                if len(data) > max_member_bytes:
                    raise UndoError(f"config {name} is too large")
                result[name] = data
    except UndoError:
        raise
    except (tarfile.TarError, OSError, EOFError):
        raise UndoError("backup cannot be read") from None
    return result


def md5_hex(data: bytes) -> str:
    """The md5 of the bytes, in lower case hex."""
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def config_base_hash(tar_path: Path, max_member_bytes: int = 1_048_576) -> str:
    """The base hash the router would have sealed for the config in a backup tarball.

    It is the sha256 of the router's ``confighash`` text: one ``<md5> <name>``
    line per regular file of /etc/config, names in byte order, a newline after
    each line.  Raises UndoError when the tarball cannot be read.
    """
    sums: dict[str, str] = {}
    try:
        with tarfile.open(tar_path, mode="r:gz") as archive:
            for member in archive:
                name = _member_config_name(member.name)
                if name is None or not member.isfile():
                    continue
                if member.size > max_member_bytes:
                    raise UndoError(f"config {name} is too large")
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                data = handle.read()
                if len(data) > max_member_bytes:
                    raise UndoError(f"config {name} is too large")
                sums[name] = md5_hex(data)
    except UndoError:
        raise
    except (tarfile.TarError, OSError, EOFError):
        raise UndoError("backup cannot be read") from None
    text = "".join(f"{sums[name]} {name}\n" for name in sorted(sums, key=lambda n: n.encode()))
    return hashlib.sha256(text.encode("ascii")).hexdigest()
