"""Strict loading and filling of per-vendor read-only getter files."""

from __future__ import annotations

import datetime
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, NoReturn

from . import registry


class GetterError(ValueError):
    """A refusal from getter loading, grammar checking, or slot filling."""


GETTER_IDS = (
    "version",
    "interfaces",
    "routes",
    "firewall_policy",
    "nat",
    "mgmt_services",
    "admins",
    "logging",
    "ntp",
    "vpn",
    "running_config",
)

SHARED_ERROR_MARKERS = (
    r"% Invalid input",
    r"% Authorization failed",
    r"syntax error",
    r"Unknown command",
    r"\[confirm\]",
)

PIPE_SUFFIXES: dict[str, frozenset[str]] = {
    "routeros": frozenset(),
    "vyos": frozenset(),
    "junos": frozenset({"no-more", "display json"}),
    "eos": frozenset({"json"}),
    "iosxe": frozenset(),
    "fortios": frozenset(),
}

DENY_TOKENS = frozenset(
    {
        "request",
        "clear",
        "execute",
        "diagnose",
        "configure",
        "debug",
        "copy",
        "save",
        "start",
        "bash",
        "run",
        "generate",
        "install",
        "write",
        "reload",
        "delete",
        "set",
        "commit",
        "monitor",
        "tech",
        "tech-support",
        "reboot",
        "shutdown",
    }
)

DENY_SUBSTRINGS = (
    "file=",
    "tftp:",
    "scp:",
    "ftp:",
    "http:",
    "https:",
    "show-sensitive",
    "tech-support",
)

_GETTER_ID_SET = frozenset(GETTER_IDS)
_SLOT_TOKEN_RE = re.compile(r"\{[a-z][a-z0-9_]{0,15}\}")
_SLOT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,15}$")
_HEAD_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*")
_ROUTEROS_WORD_RE = re.compile(r"[a-z0-9-]+")
_VERIFIED_RE = re.compile(
    r"^lab:[A-Za-z0-9._-]{1,64}:[A-Za-z0-9._-]{1,32}:(\d{4}-\d{2}-\d{2})$"
)
_OS_RANGE_RE = re.compile(r"^[A-Za-z0-9 .<>=,*-]{0,64}$")
_SOURCE_RE = re.compile(r"https://[^\s\x00-\x1f\x7f]*")
_LEDGER_RE = re.compile(r"^[A-Z][A-Z0-9-]{1,31}$")
_VALUE_BACKSTOP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$")
_COMPILED_SHARED_MARKERS = tuple(
    re.compile(source) for source in SHARED_ERROR_MARKERS
)
_PARAM_PROBES = (
    "",
    "-",
    "-x",
    "-a1",
    "a;b",
    "a|b",
    "a&b",
    "a$b",
    "a\\b",
    "a>b",
    "a<b",
    "a(b",
    "a)b",
    "a*b",
    "a?b",
    "a`b",
    "a b",
    "a\nb",
    "a\rb",
    "a\tb",
    "a\n",
    "a{b",
    "a}b",
    "a'b",
    'a"b',
    "a=b",
    "x" * 65,
)
_SHOW_HEAD_PLATFORMS = frozenset({"junos", "eos", "iosxe", "vyos"})
_ROUTEROS_PRINT_AFTER = frozenset({"detail", "terse", "without-paging", "brief"})
_ROUTEROS_EXPORT_AFTER = frozenset({"terse", "verbose", "compact", "hide-sensitive"})
_ROW_ALLOWED_KEYS = frozenset(
    {
        "id",
        "command",
        "params",
        "timeout_s",
        "max_bytes",
        "secret_bearing",
        "enabled",
        "error_markers",
        "why",
        "expect",
        "verified",
        "os_range",
        "source",
        "ledger",
    }
)
_ROW_REQUIRED_KEYS = frozenset(
    {"id", "command", "enabled", "verified", "why", "expect"}
)
_TOP_ALLOWED_KEYS = frozenset({"platform", "getter"})


@dataclass(frozen=True)
class ShapeEntry:
    """One parsed `expect` entry: alternatives of leading-token patterns."""

    source: str
    alternatives: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class Getter:
    """One immutable, allowlisted read-only getter."""

    id: str
    command: str
    params: Mapping[str, str]
    timeout_s: int
    max_bytes: int
    secret_bearing: bool
    enabled: bool
    error_markers: tuple[re.Pattern[str], ...]
    why: str
    expect: tuple[ShapeEntry, ...]
    verified: str
    os_range: str
    source: str
    ledger: str


def _refuse(platform: str, rule: str, getter_id: str | None = None) -> NoReturn:
    """Raise the module's single refusal type with a fixed diagnostic."""
    if getter_id is None:
        raise GetterError(f"{platform}: {rule}")
    raise GetterError(f"{platform} getter {getter_id}: {rule}")


def _command_text_is_valid(command: str) -> bool:
    """Check the transport-safe command character and spacing contract."""
    return (
        1 <= len(command) <= 200
        and all(0x20 <= ord(char) <= 0x7E for char in command)
        and not command.startswith(" ")
        and not command.endswith(" ")
        and "  " not in command
    )


def _check_routeros_grammar(platform: str, command: str) -> None:
    """Check RouterOS's slash-path grammar."""
    segments = command.split(" | ")
    if len(segments) != 1 or "{" in command or "}" in command:
        _refuse(platform, "routeros commands have no slots or pipe suffixes")
    if not command.startswith("/"):
        _refuse(platform, "routeros command must start with /")

    words = command[1:].replace("/", " ").split(" ")
    if any(_ROUTEROS_WORD_RE.fullmatch(word) is None for word in words):
        _refuse(platform, "routeros path and modifier words have an invalid token")
    verb_indexes = [
        index for index, word in enumerate(words) if word in {"print", "export"}
    ]
    if len(verb_indexes) != 1:
        _refuse(platform, "routeros command must contain exactly one print/export verb")
    verb_index = verb_indexes[0]
    path = words[:verb_index]
    after = words[verb_index + 1 :]
    verb = words[verb_index]
    if not path and verb != "export":
        _refuse(platform, "routeros print requires a non-empty path")
    allowed_after = (
        _ROUTEROS_PRINT_AFTER if verb == "print" else _ROUTEROS_EXPORT_AFTER
    )
    if any(word not in allowed_after for word in after):
        _refuse(platform, "routeros command has an unlisted post-verb modifier")


def _deny_list_check(platform: str, command: str) -> None:
    """Apply the read-only deny list after the positive grammar passes."""
    lowered = command.lower()
    tokens = lowered.replace("/", " ").split(" ")
    if any(
        token in DENY_TOKENS
        or (len(token) >= 3 and "tech-support".startswith(token))
        for token in tokens
    ):
        _refuse(platform, "deny-list token is forbidden")
    if any(substring in lowered for substring in DENY_SUBSTRINGS):
        _refuse(platform, "deny-list substring is forbidden")


def check_command(platform: str, command: str) -> None:
    """Refuse every command outside the platform's positive read-only grammar."""
    if (
        type(platform) is not str
        or platform not in registry.PLATFORMS
        or platform == "openwrt"
    ):
        _refuse(platform if type(platform) is str else "unknown", "platform has no getter grammar")
    if type(command) is not str or not _command_text_is_valid(command):
        _refuse(platform, "command text violates the strict shape")

    if platform == "routeros":
        _check_routeros_grammar(platform, command)
        _deny_list_check(platform, command)
        return

    segments = command.split(" | ")
    allowed_suffixes = PIPE_SUFFIXES[platform]
    used_suffixes: set[str] = set()
    for segment in segments[1:]:
        if "|" in segment or segment not in allowed_suffixes:
            _refuse(platform, "command uses an unlisted pipe suffix")
        if segment in used_suffixes:
            _refuse(platform, "command repeats a pipe suffix")
        used_suffixes.add(segment)

    slots: list[str] = []
    for token in segments[0].split(" "):
        slot_match = _SLOT_TOKEN_RE.fullmatch(token)
        if slot_match is not None:
            slot = token[1:-1]
            if slot in slots:
                _refuse(platform, "command repeats a parameter slot")
            slots.append(slot)
        elif _HEAD_TOKEN_RE.fullmatch(token) is None:
            _refuse(platform, "command head contains an invalid token")

    head_tokens = segments[0].split(" ")
    if len(head_tokens) >= 2 and _SLOT_TOKEN_RE.fullmatch(head_tokens[1]) is not None:
        _refuse(platform, "command head must name an object before any slot")

    first = head_tokens[0]
    if platform in _SHOW_HEAD_PLATFORMS:
        if first != "show" or len(head_tokens) < 2:
            _refuse(platform, "command head must start with show and name an object")
    elif first not in {"get", "show"} or len(head_tokens) < 2:
        _refuse(platform, "command head must start with get or show and name an object")

    _deny_list_check(platform, command)


def check_param_pattern(
    platform: str, getter_id: str, slot: str, pattern: str
) -> None:
    """Refuse a parameter regex that can admit command metacharacters."""
    fixed_rule = "parameter pattern must be anchored and exclude unsafe probes"
    if type(pattern) is not str:
        _refuse(platform, fixed_rule, getter_id)
    if (
        len(pattern) > 200
        or not pattern.startswith("^")
        or not pattern.endswith("$")
        or pattern.endswith("\\$")
    ):
        _refuse(platform, f"slot {slot}: parameter pattern shape is invalid", getter_id)
    try:
        compiled = re.compile(pattern)
    except re.error:
        _refuse(platform, f"slot {slot}: parameter pattern does not compile", getter_id)
    if any(compiled.fullmatch(probe) is not None for probe in _PARAM_PROBES):
        _refuse(platform, f"slot {slot}: parameter pattern admits an unsafe probe", getter_id)


_EXPECT_MAX_LEN = 200
_EXPECT_MAX_ALT_TOKENS = 12
_EXPECT_MAX_ALTERNATIVES = 12
_ALT_SEPARATOR = "||"


def _token_is_valid(token: str) -> bool:
    """Accept a literal, `*`, or `prefix*`; refuse every other use of `*` or `|`."""
    if "|" in token:
        return False
    star = token.find("*")
    return star == -1 or (token == "*") or (star == len(token) - 1 and star >= 1)


def _token_is_specific(token: str) -> bool:
    """True when a token pins at least two real characters."""
    return len(token.rstrip("*")) >= 2


def parse_expect(platform: str, getter_id: str, source: Any) -> ShapeEntry:
    """Parse one `expect` entry of tokens and `||` alternatives, or refuse it."""
    if type(source) is not str or not 1 <= len(source) <= _EXPECT_MAX_LEN:
        _refuse(platform, "expect entry length must be from 1 through 200", getter_id)
    if not all(0x20 <= ord(char) <= 0x7E for char in source):
        _refuse(platform, "expect entry must be printable ASCII", getter_id)
    words = source.split(" ")
    if "" in words:
        _refuse(platform, "expect entry must use single spaces between tokens", getter_id)
    alternatives: list[list[str]] = [[]]
    for word in words:
        if word == _ALT_SEPARATOR:
            alternatives.append([])
        elif _token_is_valid(word):
            alternatives[-1].append(word)
        else:
            _refuse(platform, "expect entry has an unknown token form", getter_id)
    if len(alternatives) > _EXPECT_MAX_ALTERNATIVES:
        _refuse(platform, "expect entry may have at most 12 alternatives", getter_id)
    for alternative in alternatives:
        if not 1 <= len(alternative) <= _EXPECT_MAX_ALT_TOKENS:
            _refuse(
                platform,
                "each expect alternative must have from 1 through 12 tokens",
                getter_id,
            )
        if not any(_token_is_specific(token) for token in alternative):
            _refuse(
                platform,
                "each expect alternative needs a literal or prefix token of 2 or more characters",
                getter_id,
            )
    return ShapeEntry(source, tuple(tuple(alternative) for alternative in alternatives))


def _token_matches(pattern: str, token: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return token.startswith(pattern[:-1])
    return token == pattern


def shape_matches(entries: tuple[ShapeEntry, ...], text: str) -> bool:
    """True when every entry matches the leading tokens of some line of ``text``.

    Linear time: one split per line, bounded by the longest alternative, and no
    backtracking engine, because ``text`` is device output and so attacker-controlled.
    """
    width = max(len(alt) for entry in entries for alt in entry.alternatives)
    pending = list(entries)
    for line in text.split("\n"):
        if not line:
            continue
        tokens = line.split(None, width)
        if not tokens:
            continue
        count = len(tokens)
        still = []
        for entry in pending:
            for alt in entry.alternatives:
                if count >= len(alt) and all(
                    _token_matches(want, have) for want, have in zip(alt, tokens)
                ):
                    break
            else:
                still.append(entry)
        pending = still
        if not pending:
            return True
    return False


def _validated_params(
    platform: str,
    getter_id: str,
    value: Any,
    command: str,
) -> dict[str, str]:
    """Validate and copy the params table, matching its slots to the command."""
    if type(value) is not dict:
        _refuse(platform, "params must be a table", getter_id)
    params = value
    for slot, pattern in params.items():
        if type(slot) is not str or _SLOT_NAME_RE.fullmatch(slot) is None:
            _refuse(platform, "params contains an invalid slot name", getter_id)
        if type(pattern) is not str:
            _refuse(platform, f"slot {slot}: pattern must be a string", getter_id)
        check_param_pattern(platform, getter_id, slot, pattern)

    head = command.split(" | ", 1)[0]
    command_slots = {
        token[1:-1]
        for token in head.split(" ")
        if _SLOT_TOKEN_RE.fullmatch(token) is not None
    }
    if set(params) != command_slots:
        _refuse(platform, "params slots must exactly equal command slots", getter_id)
    return dict(params)


def _validate_row(
    platform: str, row: Any, seen: set[str]
) -> Getter:
    """Validate one [[getter]] row and return its immutable value."""
    if type(row) is not dict:
        _refuse(platform, "getter row must be a table")
    unknown = set(row) - _ROW_ALLOWED_KEYS
    if unknown:
        _refuse(platform, "getter row contains an unknown key")
    missing = _ROW_REQUIRED_KEYS - set(row)
    if missing:
        _refuse(platform, "getter row is missing a required key")

    getter_id = row["id"]
    if type(getter_id) is not str or getter_id not in _GETTER_ID_SET:
        _refuse(platform, "getter id is not in GETTER_IDS")
    if getter_id in seen:
        _refuse(platform, "duplicate getter id", getter_id)

    command = row["command"]
    if type(command) is not str or not _command_text_is_valid(command):
        _refuse(platform, "command text violates the strict shape", getter_id)
    try:
        check_command(platform, command)
    except GetterError as exc:
        raise GetterError(f"{platform} getter {getter_id}: {exc}") from exc

    enabled = row["enabled"]
    if type(enabled) is not bool:
        _refuse(platform, "enabled must be a bool", getter_id)

    secret_bearing = row.get("secret_bearing", True)
    if type(secret_bearing) is not bool:
        _refuse(platform, "secret_bearing must be a bool", getter_id)

    timeout_s = row.get("timeout_s", 15)
    if type(timeout_s) is not int or not 1 <= timeout_s <= 30:
        _refuse(platform, "timeout_s must be an int from 1 through 30", getter_id)
    max_bytes = row.get("max_bytes", 65536)
    if type(max_bytes) is not int or not 1024 <= max_bytes <= 262144:
        _refuse(platform, "max_bytes must be an int from 1024 through 262144", getter_id)

    verified = row["verified"]
    if type(verified) is not str:
        _refuse(platform, "verified must be a string", getter_id)
    verified_match = _VERIFIED_RE.fullmatch(verified)
    if verified == "unverified":
        pass
    elif verified_match is None:
        _refuse(platform, "verified must be unverified or a lab receipt", getter_id)
    else:
        try:
            datetime.date.fromisoformat(verified_match.group(1))
        except ValueError:
            _refuse(platform, "verified lab receipt date is invalid", getter_id)
    if not secret_bearing:
        if getter_id == "running_config":
            _refuse(platform, "running_config is always secret-bearing", getter_id)
        if not verified.startswith("lab:"):
            _refuse(platform, "secret_bearing false requires a lab receipt", getter_id)

    os_range = row.get("os_range", "")
    if type(os_range) is not str or _OS_RANGE_RE.fullmatch(os_range) is None:
        _refuse(platform, "os_range has an invalid shape", getter_id)
    source = row.get("source", "")
    if (
        type(source) is not str
        or len(source) > 300
        or (source != "" and _SOURCE_RE.fullmatch(source) is None)
    ):
        _refuse(platform, "source must be empty or a whitespace-free https URL", getter_id)
    ledger = row.get("ledger", "")
    if (
        type(ledger) is not str
        or (ledger != "" and _LEDGER_RE.fullmatch(ledger) is None)
    ):
        _refuse(platform, "ledger has an invalid shape", getter_id)

    raw_markers = row.get("error_markers", [])
    if type(raw_markers) is not list or len(raw_markers) > 16:
        _refuse(platform, "error_markers must be a list of at most 16 strings", getter_id)
    own_markers: list[re.Pattern[str]] = []
    for marker in raw_markers:
        if type(marker) is not str or not 1 <= len(marker) <= 200:
            _refuse(platform, "error marker length must be from 1 through 200", getter_id)
        try:
            own_markers.append(re.compile(marker))
        except re.error:
            _refuse(platform, "error marker does not compile", getter_id)

    why = row["why"]
    if (
        type(why) is not str
        or not 1 <= len(why) <= 160
        or not why.isprintable()
    ):
        _refuse(platform, "why must be one printable line of 1 through 160 characters", getter_id)
    raw_expect = row["expect"]
    if type(raw_expect) is not list or not 1 <= len(raw_expect) <= 4:
        _refuse(platform, "expect must be a list of 1 through 4 entries", getter_id)
    expect = tuple(parse_expect(platform, getter_id, entry) for entry in raw_expect)

    params = _validated_params(
        platform, getter_id, row.get("params", {}), command
    )
    return Getter(
        id=getter_id,
        command=command,
        params=MappingProxyType(params),
        timeout_s=timeout_s,
        max_bytes=max_bytes,
        secret_bearing=secret_bearing,
        enabled=enabled,
        error_markers=(*_COMPILED_SHARED_MARKERS, *own_markers),
        why=why,
        expect=expect,
        verified=verified,
        os_range=os_range,
        source=source,
        ledger=ledger,
    )


def load_getters(platform: str, path: Path | None = None) -> dict[str, Getter]:
    """Load a platform getter file in file order, or empty when none ships."""
    if (
        type(platform) is not str
        or platform not in registry.PLATFORMS
        or platform == "openwrt"
    ):
        _refuse(
            platform if type(platform) is str else "unknown",
            "platform is not a non-openwrt registry platform",
        )

    if path is None:
        path = Path(__file__).parent / platform / "getters.toml"
        if not path.exists():
            return {}
    if not path.exists():
        _refuse(platform, "explicit getter file does not exist")
    try:
        payload = path.read_bytes()
    except OSError:
        _refuse(platform, "getter file is unreadable")
    if len(payload) > 262144:
        _refuse(platform, "getter file exceeds 262144 bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        _refuse(platform, "getter file is not UTF-8")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        _refuse(platform, "getter file is not valid TOML")

    if set(data) != _TOP_ALLOWED_KEYS:
        _refuse(platform, "top-level keys must be exactly platform and getter")
    file_platform = data["platform"]
    if type(file_platform) is not str or file_platform != platform:
        _refuse(platform, "getter file platform does not match the requested platform")
    rows = data["getter"]
    if type(rows) is not list:
        _refuse(platform, "getter must be an array of tables")

    getters: dict[str, Getter] = {}
    seen: set[str] = set()
    for row in rows:
        getter = _validate_row(platform, row, seen)
        seen.add(getter.id)
        getters[getter.id] = getter
    return getters


def enabled_getters(platform: str, path: Path | None = None) -> dict[str, Getter]:
    """Return only enabled getters, preserving file order."""
    return {
        getter_id: getter
        for getter_id, getter in load_getters(platform, path).items()
        if getter.enabled
    }


def fill_command(getter: Getter, params: Mapping[str, str]) -> str:
    """Substitute whole slot tokens after validating every supplied value."""
    if set(params) != set(getter.params):
        _refuse(
            "unknown",
            "supplied parameter slots must exactly equal getter slots",
            getter.id,
        )
    for slot, pattern_source in getter.params.items():
        value = params[slot]
        if type(value) is not str:
            _refuse("unknown", f"slot {slot}: value must be a string", getter.id)
        pattern = re.compile(pattern_source)
        if pattern.fullmatch(value) is None:
            _refuse("unknown", f"slot {slot}: value does not match the getter pattern", getter.id)
        if _VALUE_BACKSTOP_RE.fullmatch(value) is None:
            _refuse("unknown", f"slot {slot}: value fails the hard backstop", getter.id)

    segments = getter.command.split(" | ")
    filled_head = [
        params[token[1:-1]] if _SLOT_TOKEN_RE.fullmatch(token) is not None else token
        for token in segments[0].split(" ")
    ]
    filled = " | ".join([" ".join(filled_head), *segments[1:]])
    _deny_list_check("unknown", filled)
    return filled
