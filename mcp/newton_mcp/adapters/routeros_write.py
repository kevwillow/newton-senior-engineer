"""The RouterOS CHR lint, the command texts and the CHR operations.

RouterOS has no native "undo" for a change: the revert is a backup plus a
scheduler entry that loads the backup when it fires, so the device-side
objects are a ``/system backup save`` and a ``/system scheduler add``.  The
two are built here from the measured text (measure/tr/chr-confirm.txt) and
they carry the fixed name ``newton-revert``: one pending revert at a time.

The agent's change text is DATA, never script text.  ``parse_lines`` splits
it into statements of words and refuses anything that could add shell or
CLI syntax; ``render_line`` turns the words back into the canonical text
the owner sees and the plan hashes; ``command_text`` turns them into the
command the device gets.  A value with a space is written with single
quotes by the agent and rendered with double quotes by the driver, which is
what the device wants.

The lint is fail-closed.  Every raw line of the agent's text is bounded
(400 characters) and free of the characters the vendor refuses, so even a
comment line cannot smuggle a metacharacter into the plan.  A token that
carries the marker text ``NEWTON-`` is refused as well: an agent token
that holds a marker could forge one in the device output.  A name that
starts with ``newton-`` is refused too, so the agent cannot write over
the revert this module owns.

The menus of the change are decided by an ALLOW list, not by a deny list.
RouterOS takes a menu case-insensitively and takes the shortest unique
abbreviation of a path, so "/SYSTEM/SCHEDULER" and "/system sch" both
reach the scheduler, and the scheduler is where the revert of Newton
lives.  The allow list holds the full lowercase menu paths, the match is
exact, and everything else is refused.  The menus the design names are
refused with their own reason, so the owner sees why.

RouterOS 7 has no candidate configuration, so the stage is the lines
themselves and the syntax is not checked before the approval.  ``:parse``
is useless as a check: measured on 7.24.5, it answered OK for an unknown
command, an unbalanced paren and a bad value (measure/tr/chr-parse.txt).
The device rejects a bad line only when it runs, so a bad line ends in a
rollback and not in a refusal.

A CHR abort is a reboot into the backup.  The session may drop right
after the load, so a dropped session is not a proof that the load
happened: the device is asked again, in fresh sessions, until it answers,
and the load has to be proven on the device (the entry of the revert is
gone and the uptime says that the device rebooted).  Only then are the
leftovers removed, and the scheduler stays as the backstop of a device
whose load did not work.

The uptime is read with a ":put".  RouterOS prints nothing for a bare
"get" over an ssh exec, so a session that answered with an empty stdout
and the exit status 0 says nothing about the uptime -- the live CHR did
exactly that, and the proof of the load failed because of it.  The
uptime comes in several forms and every one of them is read as one
number of seconds, because the uptime is the second half of the proof.

A load that is proven leaves the file of the backup on the device: the
load restores the configuration, not the files.  The file is removed
after the proof and the device is read back, because a backup file that
is still there makes the snapshot say "pending" and the driver then
reports the rollback as unknown.

The start time of the revert is a time of the DEVICE clock, so a clock
that moves after the arm moves the revert with it: the change would sit
on the device with no revert behind it.  The menus that move the clock
are therefore off the allow list, and the revert is read again after
the last change line: the entry has to be there and its next run has to
be inside the window of the change.

A menu on the allow list takes the keys the grammar allows, and that is
too much for a menu that opens a service: "/ip/dns set
allow-remote-requests=yes" opens a resolver to the world.  The menus
that need one have a table of the keys they take, and any other key on
such a menu is refused.

The export of a CHR is not the same before and after a reboot: the
export of a device that has been up for a minute holds a block that the
same device does not have right after a reboot, and the configuration is
the same in both.  The hash of the configuration is over the normalised
export, so the volatile blocks are not part of it: the plan base hash and
the hash that is read back after the reboot of the abort are the same
and a rollback ends "rolled_back" and not "unknown" although the device
is back.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable, Sequence
from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING

from .vendor_write import LintError, SessionSpec, StageResult

if TYPE_CHECKING:
    from ..vendor_change import Run, Snapshot


PLATFORM_ROUTEROS = "routeros"

MAX_LINE_CHARS = 400
MAX_STATEMENTS = 200

# How much of the agent's own text a lint message may echo.
MAX_AGENT_TEXT_CHARS = 20

# Marker text Newton puts in device output.  A token that carries it could
# forge a marker, so any token with this substring is refused.
RESERVED_MARKER_TEXT = "NEWTON-"

# The names Newton owns on the device.  One pending revert at a time, so
# the scheduler entry and the backup file have fixed names.
RESERVED_NAME_PREFIX = "newton-"
REVERT_NAME = "newton-revert"
BACKUP_FILE = f"{REVERT_NAME}.backup"

# The window of the revert is at least this many seconds.
MIN_WINDOW_S = 120

# How much slack the next run of the armed entry may have over the
# window of the change: the entry is read again after the last change
# line, and the device answers a little after the refresh that moved
# the start time.
REVERT_WINDOW_SLACK_S = 30

# The verbs a statement may carry.  Everything else is refused.
ROUTEROS_VERBS = ("add", "set", "remove", "enable", "disable")

# The verbs that change an item, so they have to name the item.
ITEM_VERBS = ("remove", "enable", "disable")

# The sections of the export that hold a state the device owns and that
# moves with the uptime of the device.  The export of a CHR that has
# been up for a minute holds a block that the same device does not have
# right after a reboot (measured on the live CHR 7.24.5):
#
#   /system keymat-provider
#   add disabled=yes key-size=0 name=default qkd-cache-size=0 \
#       qkd-certificate=*0 type=qkd
#
# The configuration is the same in both exports, but the hash over the
# text is not: the plan base hash is taken while the device is up and
# the hash after the reboot of the abort is taken while it is down
# again, so the two differ and every rollback ends "unknown" although
# the device is back (measured: every shape of the live run that had to
# be rolled back ended "unknown").  These sections are not part of the
# configuration a change touches, so they are not part of the hash.
VOLATILE_SECTIONS = frozenset(
    {
        "/system keymat-provider",
    }
)

# The headers of the volatile sections, as they are compared: the case
# does not matter to RouterOS and the spaces of the header do not
# matter to the hash.
_VOLATILE_HEADERS = frozenset(header.lower() for header in VOLATILE_SECTIONS)

# A menu word of the path.
MENU_WORD_RE = re.compile(r"[A-Za-z0-9_-]+")
# A parameter key.
KEY_RE = re.compile(r"[A-Za-z0-9_-]+")
# A bare parameter value.
VALUE_RE = re.compile(r"[A-Za-z0-9_./:@%+=,-]+")
# The content of a quoted value may hold spaces, nothing else.
QUOTED_CONTENT_RE = re.compile(r"[A-Za-z0-9 _./:@%+=,-]*")
# The value of a numbers parameter: digits, or a star and hex digits.
NUMBERS_RE = re.compile(r"(\*[0-9A-Fa-f]+|[0-9]+)")
# The host of a ping.
HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}")

# Characters the vendor refuses anywhere in the raw text.  Double quotes
# are in the set: the agent writes a value with single quotes only.  The
# star is not in the set: it is the marker of the item a numbers
# parameter selects, and it is allowed nowhere else.
FORBIDDEN_CHARS = frozenset(";|&$`\\<>(){}[]!?\"")
CONTROL_CHARS = frozenset(chr(code) for code in range(0x20)) | {chr(0x7F)}

# The menus that are refused outright, whatever the verb.  The path is
# normalised ("/ip address" and "/ip/address" are the same menu) and the
# match is on the beginning of the path, so a menu under a refused one is
# refused too.  These are the menus the design names, and
# their message says why they are refused.
REFUSED_MENU_PREFIXES = (
    ("system", "reset-configuration"),
    ("system", "reboot"),
    ("system", "shutdown"),
    ("system", "script"),
    ("system", "scheduler"),
    ("system", "backup"),
    ("system", "package"),
    ("system", "logging", "action"),
    ("import",),
    ("file",),
    ("tool",),
    ("user",),
    ("ip", "service"),
    ("ip", "ssh"),
    ("certificate",),
    ("interface", "wireless"),
    ("export",),
)

# The menus the agent may touch.  A deny list cannot be safe here: RouterOS
# takes a menu case-insensitively and takes the shortest unique abbreviation
# of a path, so "/SYSTEM/SCHEDULER" and "/system sch" both reach the
# scheduler, and the scheduler is where the revert of Newton lives.  The
# allow list holds the full lowercase menu paths and the match is exact:
# another case, an abbreviation, an alias and a menu under an allowed one
# are all refused.
#
# Every menu here shows its content in the /export of the device, so the
# hash of the configuration moves when it changes (see RouterosOps.snapshot).
#
# The clock is not on the list: the start time of the revert is a time of
# the device clock, so a change of the clock moves the revert with it.
ALLOWED_MENUS = frozenset(
    {
        "/ip/address",
        "/ip/route",
        "/ip/dns",
        "/ip/firewall/filter",
        "/ip/firewall/nat",
        "/ip/firewall/address-list",
        "/ip/dhcp-server",
        "/ip/dhcp-server/network",
        "/ip/dhcp-client",
        "/ip/pool",
        "/interface/ethernet",
        "/interface/bridge",
        "/interface/bridge/port",
        "/interface/vlan",
        "/interface/list",
        "/interface/list/member",
        "/system/identity",
    }
)

# The parameter keys a menu may carry.  A menu that is not in this table
# takes any key the grammar allows; a menu that is in it takes only the
# keys named here, and any other key on such a menu is refused.
#
# The two menus here are the ones where a single key opens a service the
# owner never asked for: "/ip/dns set allow-remote-requests=yes" opens a
# resolver to the world, and the address list holds the entries of the
# firewall, so only the keys that name an entry are allowed there.
ALLOWED_PARAMS = {
    "/ip/dns": frozenset({"servers", "cache-size"}),
    "/ip/firewall/address-list": frozenset({"list", "address", "comment", "timeout"}),
}

# The texts the device prints when it refuses a line.  The exit status
# catches the rest; these catch a refusal that came with a zero status.
DEVICE_ERROR_TEXTS = (
    "failure:",
    "bad command name",
    "invalid value",
    "expected",
)

# The text the device prints when the load of the backup was accepted.
LOAD_ACCEPTED_TEXT = "System configuration restored, rebooting now"

# The marker the driver reads to name the line that failed.
LINE_ERROR_MARKER = "NEWTON-LINE-ERROR"

# The times of the armed entry, as the device prints them.  The receipt
# has to show the entry of this arm, so the times are parsed and compared,
# not looked for as words.
_START_TIME_RE = re.compile(r"start-time=(\d{2}:\d{2}:\d{2})")
_NEXT_RUN_RE = re.compile(
    r"next-run=(?P<date>\d{4}-\d{2}-\d{2}|[A-Za-z]{3}/\d{2}/\d{4}) "
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)
# The text the on-event of the entry has to carry: the load of the backup
# of Newton.  The device prints the quotes of the command around it, so
# the text is compared without them.
_REVERT_ON_EVENT = "backup load name=newton-revert"
# The clock of the device, as "/system clock print" prints it.
_CLOCK_TIME_RE = re.compile(r"time:\s*(\d{2}:\d{2}:\d{2})")
_CLOCK_DATE_RE = re.compile(r"date:\s*(\S+)")
# The months the device names them with.
_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

# The uptime of the device, in the forms RouterOS prints it.  A device
# that has been up for less than a day prints "HH:MM:SS" (measured:
# "00:00:23" right after the reboot, "05:50:42" for a device that has
# been up for hours), a device that has been up for more than a day
# prints "1d02:03:04", one that has been up for more than a week prints
# "2w1d02:03:04" and a device that has just booted prints "45s" or
# "1m23s".  Every one of them is one number of seconds.
_UPTIME_RE = re.compile(
    r"(?:(?P<weeks>\d+)w)?"
    r"(?:(?P<days>\d+)d)?"
    r"(?:(?P<hours>\d+)h)?"
    r"(?:(?P<minutes>\d+)m)?"
    r"(?:(?P<seconds>\d+)s)?"
    r"(?:(?P<colon_hours>\d+):(?P<colon_minutes>\d{2}):(?P<colon_seconds>\d{2}))?"
)
# The parts of an uptime and the seconds each of them is.
_UPTIME_PARTS = (
    ("weeks", 604800),
    ("days", 86400),
    ("hours", 3600),
    ("minutes", 60),
    ("seconds", 1),
    ("colon_hours", 3600),
    ("colon_minutes", 60),
    ("colon_seconds", 1),
)

# How long the abort waits for the device to answer after the load, and the
# step of that wait.  The wait is injected, so a test does not sleep.
LOAD_PROOF_WAIT_S = 150
LOAD_PROOF_STEP_S = 5
# How much slack the uptime proof gets.  The device reboots into the
# backup, so its uptime starts again; the slack is for a device that
# answered a moment before it rebooted.
UPTIME_SLACK_S = 60

_RECEIVED_RE = re.compile(r"received=(\d+)")

_ARM_TEMPLATE = (
    r':local t ([/system clock get time] + {window}); '
    r'/system backup save name={name} password=""; '
    r'/system scheduler add name={name} start-time=$t interval=0 '
    r'on-event="/system backup load name={name} password=\"\""; '
    r':put "armed for $t"'
)

_REFRESH_TEMPLATE = (
    r':local t ([/system clock get time] + {window}); '
    r"/system scheduler set {name} start-time=$t"
)


def _short_agent_text(text: str) -> str:
    """Return at most 20 characters of agent text, then an ellipsis."""
    if len(text) <= MAX_AGENT_TEXT_CHARS:
        return text
    return text[:MAX_AGENT_TEXT_CHARS] + "..."


def _check_token_text(text: str) -> None:
    """Refuse a token that carries the marker text or a reserved name."""
    if RESERVED_MARKER_TEXT in text:
        raise LintError("reserved marker text")
    if text.lower().startswith(RESERVED_NAME_PREFIX):
        raise LintError("reserved name")


def _check_raw_line(raw_line: str) -> None:
    """Refuse a raw line with a character the vendor does not accept."""
    for char in raw_line:
        if char in CONTROL_CHARS:
            raise LintError(
                f"refused control character {_short_agent_text(char)!r} in line"
            )
        if char in FORBIDDEN_CHARS:
            raise LintError(f"refused character {_short_agent_text(char)!r} in line")
        if ord(char) > 0x7F:
            raise LintError(
                f"refused non-ascii character {_short_agent_text(char)!r} in line"
            )


def _tokenize_line(line: str) -> list[tuple[str, bool]]:
    """Split one line into words.

    A word is a bare chunk, a quoted chunk, or a bare chunk that is
    followed by a quoted chunk ("comment='lab uplink'").  The second value
    of the pair says whether the word carried a quoted chunk: a word with
    a space in it can only come from one.
    """
    words: list[tuple[str, bool]] = []
    index = 0
    length = len(line)
    while index < length:
        if line[index] == " ":
            index += 1
            continue
        text = ""
        quoted = False
        while index < length and line[index] != " ":
            if line[index] == "'":
                end = line.find("'", index + 1)
                if end == -1:
                    raise LintError("unterminated quoted value")
                content = line[index + 1 : end]
                if not content:
                    raise LintError("empty quoted value")
                _check_token_text(content)
                if not QUOTED_CONTENT_RE.fullmatch(content):
                    raise LintError("quoted value has refused characters")
                text += content
                quoted = True
                index = end + 1
                if index < length and line[index] != " ":
                    raise LintError("missing space after token")
                break
            end = index
            while end < length and line[end] not in " '":
                end += 1
            chunk = line[index:end]
            _check_token_text(chunk)
            text += chunk
            index = end
        words.append((text, quoted))
    return words


def _menu_words(first: str) -> list[str]:
    """The menu words of a path: "/ip/address" and "/ip address" agree."""
    if not first.startswith("/"):
        raise LintError("a statement starts with a menu path")
    parts = first.split("/")
    if parts[0] != "":
        raise LintError("a statement starts with a menu path")
    words = parts[1:]
    if not words or any(not word for word in words):
        raise LintError("a statement needs a menu path")
    for word in words:
        if not MENU_WORD_RE.fullmatch(word):
            raise LintError("the menu path has refused characters")
    return words


def _split_statement(words: Sequence[str]) -> tuple[list[str], str, list[str]]:
    """Split the words of a statement into the menu, the verb and the params.

    The verb is the first word of the five.  A statement with no verb of
    the five names the word that stood in its place, so a refused verb is
    named in the message.
    """
    if not words:
        raise LintError("empty statement")
    verb_index: int | None = None
    for index, word in enumerate(words):
        if word in ROUTEROS_VERBS:
            verb_index = index
            break
    if verb_index is None:
        for word in words[1:]:
            if "=" not in word:
                raise LintError(f"refused verb {_short_agent_text(word)!r}")
        raise LintError("a statement needs a verb")
    if verb_index == 0:
        raise LintError("a statement needs a menu path")
    menu = _menu_words(words[0])
    for word in words[1:verb_index]:
        if "=" in word:
            raise LintError("a parameter cannot come before the verb")
        if not MENU_WORD_RE.fullmatch(word):
            raise LintError("the menu path has refused characters")
        menu.append(word)
    return menu, words[verb_index], list(words[verb_index + 1 :])


def _check_param(param: str) -> tuple[str, str]:
    """Check one key=value parameter and return its key and its value."""
    if "=" not in param:
        raise LintError("a parameter needs key=value")
    key, _, value = param.partition("=")
    if not KEY_RE.fullmatch(key):
        raise LintError("the parameter key has refused characters")
    _check_token_text(key)
    if not value:
        raise LintError("empty parameter value")
    _check_token_text(value)
    if key == "numbers":
        if not NUMBERS_RE.fullmatch(value):
            raise LintError("the numbers value is refused")
    elif " " in value:
        if not QUOTED_CONTENT_RE.fullmatch(value):
            raise LintError("the parameter value has refused characters")
    elif not VALUE_RE.fullmatch(value):
        raise LintError("the parameter value has refused characters")
    return key, value


def _check_statement(words: Sequence[str]) -> list[str]:
    """Refuse a statement the vendor refuses and return its canonical words.

    The canonical words are the menu split into its words, the verb and
    the parameters, so "/ip/address add x=y" and "/ip address add x=y"
    are the same statement.

    The menu is checked twice: the menus the design names are refused with
    their own reason, and then the allow list decides.  The allow list is
    the one that counts, because RouterOS takes a menu in any case and in
    its shortest unique abbreviation.

    A menu that has a table of parameter keys takes only those keys: a
    menu that opens a service with one key may not be written with it.
    """
    menu, verb, params = _split_statement(words)
    menu_text = "/" + "/".join(menu)
    lowered = [word.lower() for word in menu]
    for prefix in REFUSED_MENU_PREFIXES:
        if lowered[: len(prefix)] == list(prefix):
            raise LintError(f"refused menu {_short_agent_text(menu_text)!r}")
    if menu_text not in ALLOWED_MENUS:
        raise LintError("menu not allowed")
    if not params:
        raise LintError("a statement needs a parameter")
    allowed_keys = ALLOWED_PARAMS.get(menu_text)
    numbers = False
    for param in params:
        key, _ = _check_param(param)
        if key == "numbers":
            numbers = True
        if allowed_keys is not None and key not in allowed_keys:
            raise LintError("parameter not allowed")
    if verb in ITEM_VERBS and not numbers:
        raise LintError(
            f"the verb {_short_agent_text(verb)!r} needs a numbers parameter"
        )
    return [f"/{menu[0]}", *menu[1:], verb, *params]


def parse_lines(text: str) -> list[list[str]]:
    """Split the agent's change text into statements, each a list of words.

    Raises LintError for anything the vendor refuses: a metacharacter, a
    control or non-ascii character, a line over 400 characters, more than
    200 statements, a verb outside the five, a refused menu, a statement
    without a parameter, an empty value, a quoted value that is not
    closed and any token that carries the reserved marker text
    ``NEWTON-`` or a name that starts with ``newton-``.
    """
    statements: list[list[str]] = []
    for raw_line in text.split("\n"):
        if len(raw_line) > MAX_LINE_CHARS:
            raise LintError(
                f"line too long ({len(raw_line)} chars, max {MAX_LINE_CHARS})"
            )
        _check_raw_line(raw_line)
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        words = [word for word, _ in _tokenize_line(line)]
        statements.append(_check_statement(words))
        if len(statements) > MAX_STATEMENTS:
            raise LintError(f"too many statements (max {MAX_STATEMENTS})")
    return statements


def _split_tokens(tokens: Sequence[str]) -> tuple[list[str], str, list[str]]:
    """Split canonical words into the menu, the verb and the parameters."""
    if not tokens:
        raise LintError("empty statement")
    verb_index: int | None = None
    for index, word in enumerate(tokens):
        if index > 0 and word in ROUTEROS_VERBS:
            verb_index = index
            break
    if verb_index is None:
        raise LintError("a statement needs a verb")
    menu = _menu_words(tokens[0])
    for word in tokens[1:verb_index]:
        if not MENU_WORD_RE.fullmatch(word):
            raise LintError("the menu path has refused characters")
        menu.append(word)
    return menu, tokens[verb_index], list(tokens[verb_index + 1 :])


def _render_param(param: str, quote: str) -> str:
    """Render one parameter, quoting a value with a space."""
    key, value = _check_param(param)
    if " " in value:
        return f"{key}={quote}{value}{quote}"
    return f"{key}={value}"


def render_line(tokens: Sequence[str]) -> str:
    """Return the canonical text of one statement.

    This is the text the owner sees and the plan hashes: the menu, the
    verb and the parameters, with a value that holds a space in single
    quotes.  What comes out is what the tokenizer accepts again, so
    ``parse_lines(render_line(tokens))`` round-trips.
    """
    menu, verb, params = _split_tokens(tokens)
    parts = ["/" + " ".join(menu), verb]
    for param in params:
        parts.append(_render_param(param, "'"))
    return " ".join(parts)


def command_text(tokens: Sequence[str]) -> str:
    """Return the command the device gets for one statement.

    The menu is the space form ("/ip address"), which is the form that
    worked on RouterOS 7.24.5, and a value that holds a space is rendered
    in double quotes, which is what the device wants.
    """
    menu, verb, params = _split_tokens(tokens)
    parts = ["/" + " ".join(menu), verb]
    for param in params:
        parts.append(_render_param(param, '"'))
    return " ".join(parts)


def _window_text(window_s: int) -> str:
    """The window as the HH:MM:SS the device clock understands."""
    total = max(int(window_s), MIN_WINDOW_S)
    hours, rest = divmod(total, 3600)
    minutes, seconds = divmod(rest, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _window_s(timeout_s: int) -> int:
    """The window of the revert: at least two minutes."""
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, int):
        raise TypeError("timeout_s must be an int, not a bool")
    return max(timeout_s, MIN_WINDOW_S)


def export_command() -> SessionSpec:
    """The command that reads the configuration of the device."""
    return SessionSpec(remote="/export", stdin="")


def scheduler_count_command() -> SessionSpec:
    """The command that counts the revert scheduler entries."""
    return SessionSpec(
        remote=f"/system scheduler print count-only where name={REVERT_NAME}",
        stdin="",
    )


def backup_count_command() -> SessionSpec:
    """The command that counts the backup files of the revert."""
    return SessionSpec(
        remote=f'/file print count-only where name="{BACKUP_FILE}"',
        stdin="",
    )


def scheduler_detail_command() -> SessionSpec:
    """The command that reads the revert scheduler entry back."""
    return SessionSpec(
        remote=f"/system scheduler print detail where name={REVERT_NAME}",
        stdin="",
    )


def clock_command() -> SessionSpec:
    """The command that reads the clock of the device.

    The receipt is about the time of the device, so the time comes from
    the device and not from the host: the two may sit in another time
    zone.
    """
    return SessionSpec(remote="/system clock print", stdin="")


def arm_command(window_s: int) -> SessionSpec:
    """The arm: save the backup and add the scheduler entry that loads it.

    The backup save needs ``password=""`` and the on-event needs the
    escaped quotes, or the load inside the scheduler errors and nothing
    ever reverts (measured).
    """
    text = _ARM_TEMPLATE.format(
        window=_window_text(_window_s(window_s)), name=REVERT_NAME
    )
    return SessionSpec(remote=text, stdin="")


def refresh_command(window_s: int) -> SessionSpec:
    """The refresh: move the start time of the armed revert in place.

    The entry is set, never removed and added again: a remove and an add
    would leave a moment with no revert at all.
    """
    text = _REFRESH_TEMPLATE.format(
        window=_window_text(_window_s(window_s)), name=REVERT_NAME
    )
    return SessionSpec(remote=text, stdin="")


def statement_command(tokens: Sequence[str]) -> SessionSpec:
    """The command that runs one statement of the change."""
    return SessionSpec(remote=command_text(tokens), stdin="")


def marker_command(index: int) -> SessionSpec:
    """The command that prints the marker the driver reads.

    The marker names the line that failed, in the same form the VyOS
    script writes, so the driver reads it the same way.
    """
    return SessionSpec(remote=f':put "{LINE_ERROR_MARKER} {index}"', stdin="")


def scheduler_remove_command() -> SessionSpec:
    """The command that removes the revert scheduler entry."""
    return SessionSpec(
        remote=f"/system scheduler remove {REVERT_NAME}",
        stdin="",
    )


def backup_remove_command() -> SessionSpec:
    """The command that removes the backup file of the revert."""
    return SessionSpec(remote=f"/file remove {BACKUP_FILE}", stdin="")


def load_command() -> SessionSpec:
    """The command that loads the backup into the running configuration.

    The device reboots into the backup, so the session may drop right
    after this command.
    """
    return SessionSpec(
        remote=f'/system backup load name={REVERT_NAME} password=""',
        stdin="",
    )


def uptime_command() -> SessionSpec:
    """The command that asks the device whether it is back.

    The value is asked with a ":put": RouterOS prints nothing for a
    bare "get" over an ssh exec, so the session answered with an empty
    stdout and the exit status 0 and the uptime was not read at all
    (measured on the live CHR, chr-05.log, sessions 19 and 21).
    """
    return SessionSpec(remote=":put [/system resource get uptime]", stdin="")


def ping_command(host: str) -> SessionSpec:
    """The command that pings a peer, host charset bounded."""
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise LintError("refused ping host")
    return SessionSpec(remote=f"/ping count=3 address={host}", stdin="")


def _export_lines(text: str) -> list[str]:
    """The lines of an export: no CR and no trailing whitespace.

    The export of a device comes over a session that ends its lines
    with CR LF, and a line of the export may carry spaces at its end.
    The last line of a text that ends with a newline is not an empty
    line of the export.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line.rstrip() for line in lines]


def _is_volatile_header(line: str) -> bool:
    """True when the line is the header of a volatile section.

    A header is a line of its own: the export writes the path of the
    menu in the first column and the lines of the menu under it.
    """
    header = " ".join(line.split()).lower()
    return header in _VOLATILE_HEADERS


def normalise_export(text: str) -> str:
    """The export as the hash of the configuration sees it.

    The CR of the session goes, the comment lines go (the header of an
    export carries a timestamp), the trailing whitespace of every line
    goes, and the sections of ``VOLATILE_SECTIONS`` go as a whole: the
    header line and every line that follows it until the next line that
    starts a new section (a line that starts with a slash in the first
    column).  A line that continues the one above it (a line that ends
    with a backslash) belongs to the section above it, so it goes with
    it.

    Only a header names a section: a volatile name that appears inside
    a value is a value and it stays.
    """
    kept: list[str] = []
    in_volatile = False
    for line in _export_lines(text):
        if in_volatile:
            if not line.startswith("/"):
                # the line belongs to the volatile section
                continue
            # a new section starts here
            in_volatile = False
        if line.startswith("#"):
            continue
        if _is_volatile_header(line):
            in_volatile = True
            continue
        kept.append(line)
    return "\n".join(kept)


def config_hash(text: str) -> str:
    """The hash of an exported configuration.

    The hash is over the normalised export (see ``normalise_export``):
    the header of an export carries a timestamp, so the comment lines
    are left out, the trailing whitespace of the other lines is
    stripped, the CR of the session is dropped and the volatile sections
    are dropped as a whole.  The same configuration therefore hashes the
    same way on the next day and the same way before and after a
    reboot.
    """
    return hashlib.sha256(normalise_export(text).encode()).hexdigest()


def parse_count(text: str) -> int | None:
    """The number a count-only print answered, or None when it did not."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.isdigit():
            return int(stripped)
        return None
    return None


def parse_ping_received(text: str) -> int:
    """The number of packets the ping summary says came back."""
    match = _RECEIVED_RE.search(text)
    if match is None:
        return 0
    return int(match.group(1))


def _is_failure(output: Any) -> bool:
    """True when a session says the device refused the command."""
    if output.status != "ok":
        return True
    if output.exit_code not in (0, None):
        return True
    text = f"{output.stdout}\n{output.stderr}".lower()
    return any(marker in text for marker in DEVICE_ERROR_TEXTS)


def _load_accepted(output: Any) -> bool:
    """True when the device accepted the load of the backup.

    The device reboots into the backup, so the session that sent the load
    may drop right after it.  A session that came back unreachable is not
    a proof that the load happened: the abort proves the load on the
    device instead (see ``RouterosOps._load_proof``).  A load that was
    refused does not count either, and a session that says nothing about
    a restored configuration does not count.
    """
    if output.status != "ok":
        return False
    if output.exit_code not in (0, None):
        return False
    return LOAD_ACCEPTED_TEXT in output.stdout


def _load_refused(output: Any) -> bool:
    """True when the device answered and refused the load of the backup.

    A session that dropped is not a refusal: the device may be rebooting
    into the backup right now, and the device has to prove that.
    """
    if output.status != "ok":
        return False
    return not _load_accepted(output) and _is_failure(output)


def _parse_uptime(text: str) -> int | None:
    """The uptime of the device in seconds, or None when it did not say.

    RouterOS prints the uptime in several forms and every one of them
    is read here as one number of seconds: "00:00:23" for a device that
    has been up for less than a day (measured, chr-05.log: "00:00:23"
    right after the reboot and "05:50:42" for a device that has been up
    for hours), "1d02:03:04" for a device that has been up for more than
    a day, "2w1d02:03:04" for one that has been up for more than a week
    and the short forms "45s" and "1m23s" for a device that has just
    booted.

    The uptime is read word by word, because the device may print it
    with a name in front of it.  A text that carries none of the forms
    proves nothing, so it is None and not a number.
    """
    for word in text.split():
        match = _UPTIME_RE.fullmatch(word)
        if match is None:
            continue
        parts = match.groupdict()
        if not any(value is not None for value in parts.values()):
            # the word carries no part of an uptime (a number of seconds
            # on its own is not an uptime)
            continue
        seconds = 0
        for name, factor in _UPTIME_PARTS:
            value = parts[name]
            if value is not None:
                seconds += int(value) * factor
        return seconds
    return None


def _parse_date(text: str) -> date | None:
    """The date as the device prints it, or None when it did not say.

    Two forms are read: "2026-10-23" and "oct/23/2026".
    """
    text = text.strip()
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", text)
    if match is not None:
        try:
            return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            return None
    match = re.fullmatch(r"([A-Za-z]{3})/(\d{2})/(\d{4})", text)
    if match is None:
        return None
    month = _MONTHS.get(match.group(1).lower())
    if month is None:
        return None
    try:
        return date(int(match.group(3)), month, int(match.group(2)))
    except ValueError:
        return None


def _parse_clock(text: str) -> datetime | None:
    """The clock of the device, or None when it did not say.

    The clock is read from the device and not from the host: the device
    may sit in another time zone, and the receipt is about the time of
    the device.
    """
    time_match = _CLOCK_TIME_RE.search(text)
    date_match = _CLOCK_DATE_RE.search(text)
    if time_match is None or date_match is None:
        return None
    day = _parse_date(date_match.group(1))
    if day is None:
        return None
    hour, minute, second = (int(part) for part in time_match.group(1).split(":"))
    try:
        return datetime(day.year, day.month, day.day, hour, minute, second)
    except ValueError:
        return None


def _parse_next_run(text: str) -> datetime | None:
    """The next run of the entry, as the device prints it, or None."""
    match = _NEXT_RUN_RE.search(text)
    if match is None:
        return None
    day = _parse_date(match.group("date"))
    if day is None:
        return None
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    try:
        return datetime(day.year, day.month, day.day, hour, minute, second)
    except ValueError:
        return None


def _parse_start_time(text: str) -> str | None:
    """The start time of the entry as the device prints it, or None."""
    match = _START_TIME_RE.search(text)
    if match is None:
        return None
    return match.group(1)


class RouterosOps:
    """The RouterOS CHR operations of the generic driver.

    The revert of a CHR is not native: the ops arm a backup and a
    scheduler entry, read the receipt back before any change line is
    sent, and load the backup again when the change has to be undone.
    """

    platform = PLATFORM_ROUTEROS

    def __init__(
        self,
        *,
        wait: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        """The operations of a CHR.

        The wait is injected, so the wait of the abort can be driven
        without sleeping: the device is asked again in the meantime.  The
        clock is injected for the same reason: the proof of the load
        compares the uptime of the device with the time that passed, so a
        test has to be able to pin that boundary.
        """
        self._wait = wait
        self._now = now

    def snapshot(self, run: Run) -> Snapshot:
        """Read the configuration, the counts and the pending state.

        A CHR keeps its configuration as it goes, so there is no unsaved
        state to report and the reload flag is always true.

        The hash is over the /export of the device, and the /export hides
        the secrets: a password, a passphrase, a pre-shared key and a
        community do not show in it, so a change of a secret does not move
        the hash at all.  That is why the allow list of the lint holds
        only the menus whose content shows in the /export: this hash is
        the proof that a change was undone, and a hash that cannot see a
        secret would prove nothing about it.

        The hash is over the normalised export (see
        ``normalise_export``): the volatile sections of the export are
        not part of it, so the hash of the device that is up and the hash
        of the same device right after a reboot are the same.  Without
        that, the plan base hash and the hash read back after the reboot
        of the abort were different and every rollback ended "unknown"
        although the device was back.  The text of the snapshot is the
        text of the device: the export is what the device answered.
        """
        from ..vendor_change import Snapshot

        config_out = run(export_command())
        scheduler_out = run(scheduler_count_command())
        backup_out = run(backup_count_command())
        text = config_out.stdout
        pending = "unknown"
        if (
            config_out.status == "ok"
            and scheduler_out.status == "ok"
            and backup_out.status == "ok"
        ):
            scheduler_count = parse_count(scheduler_out.stdout)
            backup_count = parse_count(backup_out.stdout)
            if scheduler_count is None or backup_count is None:
                pending = "unknown"
            elif scheduler_count > 0 or backup_count > 0:
                # one pending revert at a time: a leftover of an earlier
                # revert is a pending revert as well.
                pending = "pending"
            else:
                pending = "idle"
        return Snapshot(
            text=text,
            base_hash=config_hash(text),
            reload_ok=True,
            saved_clean=True,
            pending=pending,
        )

    def stage(self, run: Run, stmts: list[list[str]]) -> StageResult:
        """Return the lines of the change as the diff of the candidate.

        A CHR has no candidate configuration, so nothing runs here.  The
        syntax is not checked either: ``:parse`` answers OK for an
        unknown command, an unbalanced paren and a bad value (measured),
        so a bad line is only found when the device runs it, and it ends
        in a rollback and not in a refusal.
        """
        diff = "\n".join(render_line(statement) for statement in stmts)
        return StageResult(ok=True, diff=diff, bad_line=None)

    def apply(self, run: Run, stmts: list[list[str]], timeout_s: int) -> str:
        """Arm the revert, read the receipt and then run the statements.

        The receipt is the read-back of the two device-side objects: no
        receipt, no change line.  Before every statement the armed entry
        is checked and its start time is moved in place, so a revert that
        fired in the meantime stops the change instead of running
        without a revert.  After the last statement the entry is read
        again: a revert that is gone, or one that fires outside the
        window of the change, does not protect the change.

        The word of the answer says what happened: "armed_failed" when
        the revert could not be armed (no change line ran at all, so
        there is nothing to undo), "revert_lost" when the revert is gone
        (it fired, so the driver has to undo the change), "line_error"
        when the device refused a line (the backup was loaded already)
        and "committed" when every line ran and the revert is still
        armed.
        """
        window = _window_s(timeout_s)
        arm_out = run(arm_command(window))
        if _is_failure(arm_out):
            # the arm did not work: the revert is not armed, so no change
            # line may run.  The leftovers go, but their state is not the
            # verdict here: the driver reads the hash back, and a file
            # that is still there makes the next plan refuse.
            self._remove_leftovers(run)
            return "armed_failed"
        if not self._receipt_ok(run):
            self._remove_leftovers(run)
            return "armed_failed"
        for index, tokens in enumerate(stmts, start=1):
            check_out = run(scheduler_count_command())
            if not self._still_pending(check_out):
                # the entry is gone: the revert fired and there is no
                # revert left for this change.
                return "revert_lost"
            refresh_out = run(refresh_command(window))
            if _is_failure(refresh_out):
                # the entry is gone: the revert fired and there is no
                # revert left for this change.
                return "revert_lost"
            out = run(statement_command(tokens))
            if _is_failure(out):
                run(marker_command(index))
                self.abort(run)
                return "line_error"
        if not self._revert_still_armed(run, window):
            # the change is on the device and the revert is not where it
            # has to be: the driver has to take the recover path.
            return "revert_lost"
        return "committed"

    def confirm(self, run: Run) -> bool:
        """Remove the armed revert, but only when the device says it is gone.

        The scheduler entry goes first and the backup file second: a
        scheduler that fires in the gap between the two would run its
        on-event against a backup file that is already gone, and the
        revert would fail silently.  The device is read back afterwards:
        a confirm that only removed something is not a confirm.
        """
        scheduler_out = run(scheduler_remove_command())
        backup_out = run(backup_remove_command())
        if scheduler_out.status != "ok" or scheduler_out.exit_code != 0:
            return False
        if backup_out.status != "ok" or backup_out.exit_code != 0:
            return False
        scheduler_check = run(scheduler_count_command())
        backup_check = run(backup_count_command())
        if scheduler_check.status != "ok" or backup_check.status != "ok":
            return False
        scheduler_count = parse_count(scheduler_check.stdout)
        backup_count = parse_count(backup_check.stdout)
        return scheduler_count == 0 and backup_count == 0

    def save(self, run: Run) -> bool:
        """A CHR keeps its configuration as it goes, so there is no save."""
        return True

    def abort(self, run: Run) -> bool:
        """Load the backup again, then remove what the revert left behind.

        The load comes first: the scheduler entry is the backstop and it
        stays as long as the load did not work.  The device reboots into
        the backup, so the session that sent the load may drop, and a
        dropped session is not a proof that the load happened.  The device
        is asked again, in fresh sessions, until it answers, and the load
        has to be proven: the entry of the revert is gone (the load
        restored the configuration of the backup, which was taken before
        the entry existed) and the uptime says that the device rebooted.

        A load the device denies is sent once more.  A load that cannot
        be proven twice leaves the entry and the backup file in place:
        they are the backstop of a device that is still changed.  A load
        that is proven removes the leftovers and reads them back: a
        backup file that is still there makes the snapshot say
        "pending", and the driver reports the rollback as unknown.
        """
        for _ in range(2):
            sent_at = self._now()
            out = run(load_command())
            if _load_refused(out):
                proof: bool | None = False
            else:
                proof = self._load_proof(run, sent_at)
            if proof is True:
                return self._remove_leftovers(run)
            if proof is None:
                # the device never answered: what happened is not known,
                # and a second load would reboot a device that may be up.
                return False
        return False

    def pending(self, run: Run) -> str:
        """Read the state of the armed revert."""
        out = run(scheduler_count_command())
        if out.status != "ok":
            return "unknown"
        count = parse_count(out.stdout)
        if count is None:
            return "unknown"
        return "pending" if count > 0 else "idle"

    def probe_ping(self, run: Run, host: str) -> bool:
        """Ping a peer and require one packet to come back."""
        out = run(ping_command(host))
        if out.status != "ok":
            return False
        return parse_ping_received(out.stdout) >= 1

    def has_line(self, snapshot_text: str, rendered_line: str) -> bool:
        """Never claim that a configuration holds a line.

        The export of a CHR normalises the lines: it writes the menu and
        the parameters its own way, so a claim cannot be compared with it
        reliably.  The claim kind ``config_has`` is refused for routeros
        in the explanation layer; until then this matcher never
        claims a hit, and the only claim kind that works is the ping.
        """
        return False

    def _receipt_ok(self, run: Run) -> bool:
        """Read the two device-side objects back: the receipt of the arm.

        The receipt is the entry of this arm: the backup file is there,
        the on-event is the load of that backup, and the entry fires at a
        moment that parses.  The words of the device are not enough: an
        entry of an earlier run carries the same words, so the next run
        is parsed and compared with the clock of the device, and the
        entry has to be one that has not fired yet.

        When the device does not say what time it is, the receipt proves
        what it can: the file is there, the on-event is the load of that
        backup and the next run parses.
        """
        file_out = run(backup_count_command())
        detail_out = run(scheduler_detail_command())
        if file_out.status != "ok" or detail_out.status != "ok":
            return False
        if parse_count(file_out.stdout) != 1:
            return False
        text = detail_out.stdout
        if _REVERT_ON_EVENT not in text:
            return False
        next_run = _parse_next_run(text)
        if next_run is None:
            return False
        start = _parse_start_time(text)
        if start is not None and start != next_run.strftime("%H:%M:%S"):
            # the entry does not fire when it starts: it is not the entry
            # that was armed.
            return False
        clock_out = run(clock_command())
        if clock_out.status != "ok":
            return False
        clock = _parse_clock(clock_out.stdout)
        if clock is None:
            return True
        return next_run > clock

    def _still_pending(self, output: Any) -> bool:
        """True when the armed entry is still on the device."""
        if output.status != "ok":
            return False
        count = parse_count(output.stdout)
        return count is not None and count > 0

    def _revert_still_armed(self, run: Run, window: int) -> bool:
        """True when the revert is still there and still inside its window.

        The revert of a CHR is a scheduler entry, and the entry fires at
        a time of the device clock.  A clock that moves after the arm
        moves the entry with it, so the entry and the clock are read
        again once the change is on the device: the entry has to be there
        and its next run has to be inside the window of the change (the
        clock of the device, the window and a small slack).

        A next run in the past has fired already, and a next run beyond
        the window fires too late to protect this change: both are not a
        revert that is armed.

        A device that does not say what time it is cannot be checked this
        way: the entry is then only required to be there.
        """
        count_out = run(scheduler_count_command())
        if not self._still_pending(count_out):
            return False
        detail_out = run(scheduler_detail_command())
        if detail_out.status != "ok":
            return False
        next_run = _parse_next_run(detail_out.stdout)
        if next_run is None:
            return False
        clock_out = run(clock_command())
        if clock_out.status != "ok":
            return False
        clock = _parse_clock(clock_out.stdout)
        if clock is None:
            # the device does not say what time it is: nothing more can
            # be proven about the window.
            return True
        if next_run <= clock:
            # the entry has fired already (or fires now).
            return False
        return next_run <= clock + timedelta(seconds=window + REVERT_WINDOW_SLACK_S)

    def _load_proof(self, run: Run, sent_at: float) -> bool | None:
        """Prove that the load of the backup happened.

        True when the device proves it, False when the device says that
        it did not happen, and None when the device never answered.  The
        wait is bounded twice over: by the number of steps and by the
        time it may take, so a host that never answers cannot hold the
        rollback open.
        """
        waited = 0.0
        while True:
            scheduler_out = run(scheduler_count_command())
            uptime_out = run(uptime_command())
            if scheduler_out.status == "ok" and uptime_out.status == "ok":
                break
            if waited >= LOAD_PROOF_WAIT_S:
                return None
            self._wait(LOAD_PROOF_STEP_S)
            waited += LOAD_PROOF_STEP_S
        count = parse_count(scheduler_out.stdout)
        uptime = _parse_uptime(uptime_out.stdout)
        if count is None or uptime is None:
            return None
        if count > 0:
            # the entry of the revert is still there: the load did not
            # restore the configuration of the backup.
            return False
        # the device has to have rebooted since the load was sent.
        return uptime < (self._now() - sent_at) + UPTIME_SLACK_S

    def _remove_leftovers(self, run: Run) -> bool:
        """Remove the scheduler entry and the backup file, then read them back.

        The scheduler goes first and the backup file second, the same
        order the confirm uses: a scheduler that fires in the gap
        between the two would run its on-event against a backup file
        that is already gone.

        The read-back is what counts.  A load restores the configuration
        of the backup, not the files of the device, so the file of the
        backup is still there after the load (measured on the live CHR)
        and a file that is still there makes the snapshot say "pending":
        the driver then reports the rollback as unknown.  A removal
        that was not read back is not a removal.
        """
        run(scheduler_remove_command())
        run(backup_remove_command())
        scheduler_out = run(scheduler_count_command())
        file_out = run(backup_count_command())
        if scheduler_out.status != "ok" or file_out.status != "ok":
            return False
        return (
            parse_count(scheduler_out.stdout) == 0
            and parse_count(file_out.stdout) == 0
        )

