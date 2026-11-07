"""The Junos lint, the command texts and the Junos operations.

Junos has a native revert: ``commit confirmed N`` arms the device with a
rollback that fires in N minutes unless the change is confirmed.  The arm
and the change are ONE commit, so there is no window in which the change
is on the device without a revert behind it (the VyOS path arms the timer
and then writes the lines; the CHR path arms a scheduler entry).

The session of a Junos device is one ssh with NO remote command and the
CLI script on stdin (measured on 26.2R1.7, measure/tr/junos-confirm.txt):
the login shell of the device is the CLI, so the script is read by the CLI
and the input is echoed after the prompt.  There is no tty, so
``load set terminal`` does not work and the exit status says nothing: a
refused line prints "syntax error." and the CLI carries on.

The agent's change text is DATA, never CLI text.  ``parse_lines`` splits
it into statements of words and refuses anything that could add CLI
syntax; ``render_line`` turns the words back into the canonical text the
owner sees and the plan hashes; ``command_text`` turns them into the line
the device gets, with a value that holds a space in double quotes.

The lint is fail-closed.  Every raw line of the agent's text is bounded
(400 characters) and free of the characters the vendor refuses, so even a
comment line cannot smuggle a metacharacter into the plan.  A token that
carries the marker text ``NEWTON-`` is refused as well: an agent token
that holds a marker could forge one in the device output.

The hierarchies of the change are decided by an ALLOW list, not by a deny
list.  Junos takes a hierarchy in an abbreviated form ("sys host-name"
reaches "system host-name") and in any case, so a deny list cannot be
safe here.  The allow list holds the full lowercase hierarchies, the
match is on the words and it is exact: another case, an abbreviation and
a hierarchy under an allowed one are all refused.

The stage is a candidate: the lines go into a configuration session that
is thrown away again ("rollback 0"), so the plan shows a real diff and a
real syntax check before any approval.  The error detection is on the
output of the session and it fails closed: after the echo of a statement
the only acceptable output is nothing at all or an ``[edit ...]`` marker,
so a "syntax error." (or an "error:", a "warning:", an "unknown command"
or a "missing argument") is a line error and it names the statement.

The apply stages again in a fresh session first, so a line that the
device refuses is refused before anything is committed and nothing is
armed.  The candidate of that stage is hashed, and the driver reads the
configuration back after the commit: a commit that is not the candidate
that was staged is a partial or a concurrent change, and the driver takes
the revert.

Every read is a session of the CLI as well, so the candidate of a stage
and the running configuration of a snapshot are read the same way: the
block between the echo of the command and the next prompt.  One
normaliser hashes both, and the banner and the prompts of the CLI are
not part of the hash.

The commit of Newton carries a tag ("commit confirmed N comment
newton-pending"), so the commit list of the device tells which commit is
ours.  The abort reads that list before it rolls anything back: the
rollback of the commit before the change is the change only when the
commit of Newton is still the top entry and its revert is still
pending.  Once the armed revert has fired, the rollback of the device
is a commit of its own, and "rollback 1" would put the change back with
no revert armed, so the abort does nothing then.  The device shows an
entry it rolled back by itself with the same text as any other entry,
so the abort may only say that the change is gone when the visible list
carries no commit of Newton at all; every other state is ambiguous and
the abort says that it does not know.  The confirm is a commit in a
session of its own, and the driver reads the configuration back after
it: a confirm alone does not say that the change is still on the
device.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .vendor_write import (
    MAX_MINUTES,
    MIN_MINUTES,
    LintError,
    SessionSpec,
    StageResult,
    minutes_for,
)

if TYPE_CHECKING:
    from ..vendor_change import Run, Snapshot


PLATFORM_JUNOS = "junos"

MAX_LINE_CHARS = 400
MAX_STATEMENTS = 200

# How much of the agent's own text a lint message may echo.
MAX_AGENT_TEXT_CHARS = 20

# Marker text Newton puts in device output.  A token that carries it could
# forge a marker, so any token with this substring is refused.
RESERVED_MARKER_TEXT = "NEWTON-"

# The word that tags the commit of Newton.  The commit that arms the
# revert carries it, so the commit list of the device tells which commit
# is ours.  The word is reserved: an agent token with it could forge the
# tag of a commit that is not ours.
COMMIT_TAG = "newton-pending"

# The verbs a statement may carry.  Everything else is refused: "request",
# "load", "commit", "rollback" and "run" are the verbs of the device, not
# of a change.
JUNOS_VERBS = ("set", "delete", "activate", "deactivate")

# The hierarchies the agent may touch.  The match is on the words and it
# is exact: no abbreviation, no other case and no hierarchy under one of
# these.
#
# "system login", "system services", "snmp", "event-options" and "system
# scripts" are not on the list: the first two open the way in, the third
# reads what the device says about itself and the last two run code on
# the device.
ALLOWED_HIERARCHIES = (
    ("security", "zones"),
    ("security", "policies"),
    ("security", "nat"),
    ("system", "host-name"),
    ("system", "name-server"),
    ("system", "ntp"),
    ("system", "time-zone"),
    ("interfaces",),
    ("vlans",),
    ("routing-options",),
    ("protocols",),
    ("policy-options",),
    ("firewall",),
)

# A bare word is a hierarchy element or a value without a space.
BARE_WORD_RE = re.compile(r"[A-Za-z0-9_./:@%+=,-]+")
# The content of a quoted value of the agent's text may hold spaces,
# nothing else.
QUOTED_CONTENT_RE = re.compile(r"[A-Za-z0-9 _./:@%+=,-]*")
# The host of a ping.
HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}")

# The device's own text is only ever read, never sent back to the device,
# so its words may hold any printable character except the quote that
# opens a value.
DEVICE_WORD_RE = re.compile(r"[!-~]+")
DEVICE_QUOTED_RE = re.compile(r"[^\x00-\x1f\x7f]*")

# Characters the vendor refuses anywhere in the raw text.  Double quotes
# are in the set: the agent writes a value with single quotes only.
FORBIDDEN_CHARS = frozenset(";|&$`\\<>(){}[]!?\"")
CONTROL_CHARS = frozenset(chr(code) for code in range(0x20)) | {chr(0x7F)}

# The command that reads the configuration of the device.  The pipe is
# Junos CLI syntax and not a shell pipe: the login shell of the device is
# the CLI (measured on 26.2R1.7).
CONFIG_COMMAND = "show configuration | display set | no-more"
CANDIDATE_COMMAND = "show | display set | no-more"
# The command that reads the commit list of the device.  A revert that is
# pending shows there as "rollback pending".
PENDING_COMMAND = "show system commit | no-more"

# The text the device prints when a commit went through.  It has to be a
# line of its own: a description that quotes it is not a commit.
COMMITTED_TEXT = "commit complete"

# The text the device prints when the armed revert will fire.  The notice
# has to be a line of its own that starts with these words: the echo of a
# command and a value of the change can carry the same words, and
# neither of them says that anything is armed.
_ARM_NOTICE_RE = re.compile(
    r"^commit confirmed will be automatically rolled back in (\d+) minutes\b"
)

# The line the device prints under an entry of the commit list when the
# revert of that entry is pending.
PENDING_TEXT = "rollback pending"

# The header of an entry of the commit list: the number of the entry and
# the rest of the line.
_COMMIT_ENTRY_RE = re.compile(r"^(?P<index>\d+)\s+(?P<rest>\S.*)$")

# The tag of the commit of Newton, as a word of the commit list.
_COMMIT_TAG_RE = re.compile(rf"\b{COMMIT_TAG}\b")

# The packet loss of a ping that came back.  The lookbehind keeps
# "100% packet loss" from counting: it ends in "0% packet loss" too.
_ZERO_LOSS_RE = re.compile(r"(?<![0-9.])0% packet loss")

# The prompt of the CLI, with the input echoed after it.  The prompt of
# the last line of a session carries nothing after it, so the echo is
# optional.
_PROMPT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+)(?P<mode>[>#])(?: (?P<echo>.*))?$"
)
# The marker the CLI prints in the configuration mode.
_EDIT_MARKER_RE = re.compile(r"^\[edit[^\]]*\]$")
_STAGE_ERROR_RE = re.compile(
    r"^(?:syntax error\.|error:|unknown command|missing argument)",
    re.IGNORECASE,
)

# The prefix of the line the device prints when it refuses a session.
# The CLI of a Junos carries on after a refusal, so the exit status of
# the session says nothing at all.
_ERROR_PREFIX = "error:"


def _refused(text: str) -> bool:
    """True when the device refused the session instead of answering it.

    A read that was refused is not an answer: the state it would carry
    (the commit list of the device, the pending revert) is unknown.
    """
    for line in text.splitlines():
        if line.strip().lower().startswith(_ERROR_PREFIX):
            return True
    return False


def _short_agent_text(text: str) -> str:
    """Return at most 20 characters of agent text, then an ellipsis."""
    if len(text) <= MAX_AGENT_TEXT_CHARS:
        return text
    return text[:MAX_AGENT_TEXT_CHARS] + "..."


def _check_token_text(text: str) -> None:
    """Refuse a token that carries the reserved marker text."""
    if RESERVED_MARKER_TEXT in text:
        raise LintError("reserved marker text")
    if COMMIT_TAG in text.lower():
        raise LintError("reserved commit tag")


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


@dataclass(frozen=True)
class _Token:
    """One token of a statement and whether it was quoted."""

    value: str
    quoted: bool


def _find_quote_end(line: str, start: int, quote: str) -> int:
    """The index of the quote that closes the value at ``start``."""
    index = start + 1
    while index < len(line):
        char = line[index]
        if char == "\\" and quote == '"':
            # the device's own text may escape a quote inside a value
            index += 2
            continue
        if char == quote:
            return index
        index += 1
    raise LintError("unterminated quoted value")


def _tokenize_line(line: str, *, device: bool = False) -> list[_Token]:
    """Split one statement into tokens; refuse anything malformed.

    The agent's text quotes a value with single quotes and the device's
    display-set text quotes it with double quotes, so the quote character
    is a parameter: the agent's text never takes a double quote and the
    device's text never takes a single one.
    """
    quote = '"' if device else "'"
    tokens: list[_Token] = []
    index = 0
    length = len(line)
    while index < length:
        if line[index] == " ":
            index += 1
            continue
        if line[index] == quote:
            end = _find_quote_end(line, index, quote)
            content = line[index + 1 : end]
            if not content:
                raise LintError("empty quoted value")
            if device:
                if not DEVICE_QUOTED_RE.fullmatch(content):
                    raise LintError("quoted value has refused characters")
            else:
                _check_token_text(content)
                if not QUOTED_CONTENT_RE.fullmatch(content):
                    raise LintError("quoted value has refused characters")
            tokens.append(_Token(content, True))
            index = end + 1
        else:
            end = index
            while end < length and line[end] != " " and line[end] != quote:
                end += 1
            word = line[index:end]
            if device:
                if not DEVICE_WORD_RE.fullmatch(word):
                    raise LintError("token has refused characters")
            else:
                _check_token_text(word)
                if not BARE_WORD_RE.fullmatch(word):
                    raise LintError("token has refused characters")
            tokens.append(_Token(word, False))
            index = end
        if index < length and line[index] != " ":
            raise LintError("missing space after token")
    return tokens


def _match_hierarchy(
    values: Sequence[str],
    quoted: Sequence[bool],
) -> tuple[str, ...] | None:
    """The hierarchy a statement starts with, or None when it has none.

    The longest hierarchy of the allow list wins, so a hierarchy under an
    allowed one ("security zones" under "security") cannot slip in.  The
    match is on the words and it is exact: Junos takes an abbreviation of
    a hierarchy and any case, and neither may reach the device.
    """
    for prefix in ALLOWED_HIERARCHIES:
        if len(prefix) > len(values):
            continue
        if any(quoted[: len(prefix)]):
            continue
        if tuple(values[: len(prefix)]) == prefix:
            return prefix
    return None


def _check_values(values: Sequence[str], quoted: Sequence[bool]) -> None:
    """Refuse a statement the vendor refuses.

    The verb comes first, so a refused verb is named.  Then the
    hierarchy: the allow list is the one that counts, because Junos takes
    a hierarchy in an abbreviated form and in any case.
    """
    if not values:
        raise LintError("empty statement")
    verb = values[0]
    if verb not in JUNOS_VERBS:
        raise LintError(f"refused verb {_short_agent_text(verb)!r}")
    prefix = _match_hierarchy(values[1:], quoted[1:])
    if prefix is None:
        raise LintError("hierarchy not allowed")
    if len(values) <= 1 + len(prefix):
        raise LintError("a statement needs a value")


def _check_statement(tokens: Sequence[_Token]) -> list[str]:
    """Refuse a statement the vendor refuses and return its words."""
    values = [token.value for token in tokens]
    _check_values(values, [token.quoted for token in tokens])
    return values


def parse_lines(text: str) -> list[list[str]]:
    """Split the agent's change text into statements, each a list of words.

    Raises LintError for anything the vendor refuses: a metacharacter, a
    control or non-ascii character, a line over 400 characters, more than
    200 statements, a verb outside the four, a hierarchy that is not on
    the allow list, a statement without a value, an empty quoted value
    (``''``) and any token that carries the reserved marker text
    ``NEWTON-``.
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
        tokens = _tokenize_line(line)
        statements.append(_check_statement(tokens))
        if len(statements) > MAX_STATEMENTS:
            raise LintError(f"too many statements (max {MAX_STATEMENTS})")
    return statements


def _render(tokens: Sequence[str], quote: str) -> str:
    """Render the words of one statement, quoting a value with a space."""
    parts: list[str] = []
    for token in tokens:
        if not isinstance(token, str) or not token:
            raise LintError("empty token")
        _check_token_text(token)
        if " " in token:
            if not QUOTED_CONTENT_RE.fullmatch(token):
                raise LintError("token has refused characters")
            parts.append(f"{quote}{token}{quote}")
        else:
            if not BARE_WORD_RE.fullmatch(token):
                raise LintError("token has refused characters")
            parts.append(token)
    return " ".join(parts)


def render_line(tokens: Sequence[str]) -> str:
    """Return the canonical text of one statement.

    This is the text the owner sees and the plan hashes: the verb, the
    hierarchy and the values, with a value that holds a space in single
    quotes.  What comes out is what the tokenizer accepts again, so
    ``parse_lines(render_line(tokens))`` round-trips.

    The statement is checked against the rules of the vendor here as
    well, so the renderer cannot become a way round the allow list.
    """
    values = list(tokens)
    _check_values(values, [False] * len(values))
    return _render(values, "'")


def command_text(tokens: Sequence[str]) -> str:
    """Return the line the device gets for one statement.

    A value that holds a space is rendered in double quotes, which is the
    form the device writes back in its display-set output, so the
    configuration of the device and the change text can be compared.
    """
    values = list(tokens)
    _check_values(values, [False] * len(values))
    return _render(values, '"')


def config_hash(text: str) -> str:
    """The hash of a display-set configuration.

    The lines that start with a hash are left out: the CLI prints its
    notices that way ("# commit confirmed will be rolled back in 5
    minutes") and so does the configuration itself ("## Last commit:").
    The empty lines are left out as well: the CLI puts one between its
    output and the prompt, and the candidate of a stage and the running
    configuration of a snapshot have to hash the same way.
    """
    lines = [
        line.rstrip()
        for line in text.splitlines()
        if not line.startswith("#") and line.strip()
    ]
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def parse_pending(text: str) -> bool:
    """True when the device says that a revert is pending.

    The phrase counts only on a line of its own under an entry of the
    commit list: a commit comment that quotes it is not a pending
    revert.
    """
    return any(entry.pending for entry in parse_commit_list(text))


def parse_committed(text: str) -> bool:
    """True when the device printed the commit text on a line of its own."""
    for line in text.splitlines():
        if line.strip() == COMMITTED_TEXT:
            return True
    return False


def _has_rollback_notice(text: str, minutes: int) -> bool:
    """True when the device printed the notice of the armed revert.

    The notice has to be a line of its own that starts with the words of
    the notice, and the number of minutes has to be the one the driver
    asked for: a notice of another window is not the revert of this
    change.  A line that starts with the prompt of the CLI is the echo
    of a command and never the notice.
    """
    for line in text.splitlines():
        stripped = line.strip()
        if _PROMPT_RE.match(stripped):
            continue
        match = _ARM_NOTICE_RE.match(stripped)
        if match is None:
            continue
        if int(match.group(1)) == minutes:
            return True
    return False


@dataclass(frozen=True)
class CommitEntry:
    """One entry of the commit list of the device.

    The entry has a header (its number, the time and who committed it)
    and the lines the device prints under it.
    """

    index: int
    header: str
    lines: tuple[str, ...]

    @property
    def text(self) -> str:
        """The whole entry, as the device shows it."""
        return "\n".join((self.header, *self.lines))

    @property
    def pending(self) -> bool:
        """True when the revert of this entry is pending."""
        for line in self.lines:
            stripped = line.strip()
            if not stripped.startswith(PENDING_TEXT):
                continue
            return True
        return False

    @property
    def ours(self) -> bool:
        """True when this entry is the commit of Newton."""
        return _COMMIT_TAG_RE.search(self.text) is not None


def parse_commit_list(text: str) -> list[CommitEntry]:
    """The entries of the commit list of the device.

    An entry starts with its number and the lines under it belong to it.
    The prompts of the CLI and the empty lines are not part of an entry.
    """
    entries: list[CommitEntry] = []
    header: str | None = None
    index = 0
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if _PROMPT_RE.match(line):
            continue
        match = _COMMIT_ENTRY_RE.match(line)
        if match is not None:
            if header is not None:
                entries.append(CommitEntry(index, header, tuple(lines)))
            index = int(match.group("index"))
            header = line
            lines = []
        elif header is not None:
            lines.append(line)
    if header is not None:
        entries.append(CommitEntry(index, header, tuple(lines)))
    return entries


# What the abort has to do, from the commit list of the device.
ABORT_ROLLBACK = "rollback"
ABORT_REVERTED = "reverted"
ABORT_UNKNOWN = "unknown"


def abort_decision(entries: Sequence[CommitEntry]) -> str:
    """What the abort has to do, from the commit list of the device.

    "rollback": the commit of Newton is the top entry and its revert is
    still pending, so the rollback of the commit before it is the change.
    "reverted": the visible list carries no commit of Newton at all, so
    the device already reverted the change and there is nothing to roll
    back.
    "unknown": everything else, and the abort rolls nothing back.

    The commit of Newton under a commit of somebody else is unknown: the
    change was confirmed and it is still on the device.  The device
    shows an entry it rolled back by itself with the same text as any
    other entry, so the abort cannot tell a rolled back commit from a
    confirmed one: it says that it does not know.
    """
    if not entries:
        return ABORT_UNKNOWN
    top = entries[0]
    if top.ours and top.pending:
        return ABORT_ROLLBACK
    if not any(entry.ours for entry in entries):
        # no commit of Newton in the visible list: the device rolled the
        # change back by itself, so there is nothing to roll back.
        return ABORT_REVERTED
    # the commit of Newton is in the list and it is not the top entry
    # with a pending revert: the state is ambiguous.
    return ABORT_UNKNOWN


def config_command() -> SessionSpec:
    """The command that reads the configuration of the device.

    The read is a session of the CLI, like every other session of a
    Junos: the login shell of the device is the CLI, and the output of
    the command is the block between the echo of the command and the
    next prompt.  The candidate of a stage and the running configuration
    of a snapshot are read the same way, so one normaliser hashes both.
    """
    return SessionSpec(remote="", stdin=f"{CONFIG_COMMAND}\nexit\n")


def pending_command() -> SessionSpec:
    """The command that reads the commit list of the device.

    A revert that is pending shows there as "rollback pending".
    """
    return SessionSpec(remote="", stdin=f"{PENDING_COMMAND}\nexit\n")


def ping_command(host: str) -> SessionSpec:
    """The command that pings a peer, host charset bounded."""
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise LintError("refused ping host")
    return SessionSpec(remote=f"ping {host} count 3 rapid", stdin="")


def stage_script(stmts: Iterable[Sequence[str]]) -> SessionSpec:
    """The candidate session: the lines, the diff, the candidate, the throw away.

    The session is one ssh with the script on stdin and no remote
    command: the login shell of the device is the CLI.

    "rollback 0" throws the candidate away before the session ends, so the
    stage never changes the device, and the diff and the candidate are
    read before it.
    """
    lines = ["configure exclusive"]
    lines.extend(command_text(tokens) for tokens in stmts)
    lines.extend(
        [
            "show | compare | no-more",
            CANDIDATE_COMMAND,
            "rollback 0",
            "exit",
            "exit",
        ]
    )
    return SessionSpec(remote="", stdin="\n".join(lines) + "\n")


def apply_script(stmts: Iterable[Sequence[str]], minutes: int) -> SessionSpec:
    """The apply session: the lines and the armed commit, in one session.

    The arm and the change are one commit, so there is no window in which
    the change is on the device without a revert behind it.

    The commit carries the tag of Newton, so the commit list of the
    device tells which commit is ours: the abort needs that to know
    whether "rollback 1" is the change or the state before it.
    """
    if isinstance(minutes, bool) or not isinstance(minutes, int):
        raise TypeError("minutes must be an int")
    if not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise ValueError(f"minutes must be {MIN_MINUTES}..{MAX_MINUTES}")
    lines = ["configure exclusive"]
    lines.extend(command_text(tokens) for tokens in stmts)
    lines.append(f"commit confirmed {minutes} comment {COMMIT_TAG}")
    lines.extend(["exit", "exit"])
    return SessionSpec(remote="", stdin="\n".join(lines) + "\n")


def confirm_script() -> SessionSpec:
    """The confirm session: the commit that takes the armed revert away."""
    return SessionSpec(remote="", stdin="configure\ncommit\nexit\nexit\n")


def abort_script() -> SessionSpec:
    """The abort session: the rollback of the commit before the change."""
    return SessionSpec(
        remote="",
        stdin="configure exclusive\nrollback 1\ncommit\nexit\nexit\n",
    )


@dataclass
class _Block:
    """One command of a session and the lines the device printed after it."""

    echo: str
    output: list[str]


def _split_blocks(text: str) -> list[_Block]:
    """Split the output of a session into the command and its output.

    The input of the session is echoed after the prompt (there is no tty),
    so the prompt line holds the command and the lines after it are what
    the device said about it.
    """
    blocks: list[_Block] = []
    echo: str | None = None
    output: list[str] = []
    for line in text.splitlines():
        match = _PROMPT_RE.match(line)
        if match is None:
            if echo is not None:
                output.append(line)
            continue
        if echo is not None:
            blocks.append(_Block(echo, output))
        echo = (match.group("echo") or "").rstrip()
        output = []
    if echo is not None:
        blocks.append(_Block(echo, output))
    return blocks


def _is_blank(line: str) -> bool:
    """True when the line carries nothing but spaces and tabs."""
    return line.strip(" \t") == ""


def _statement_blocks(
    blocks: Sequence[_Block],
    commands: Sequence[str],
) -> list[_Block | None]:
    """The block of every statement, in order.

    The search starts after the block of the previous statement, so the
    same statement twice is read twice and not once.
    """
    found: list[_Block | None] = []
    start = 0
    for command in commands:
        block: _Block | None = None
        for index in range(start, len(blocks)):
            if blocks[index].echo == command:
                block = blocks[index]
                start = index + 1
                break
        found.append(block)
    return found


def _line_error(found: Sequence[_Block | None]) -> int | None:
    """The number of the statement the device refused, or None.

    Junos prints "syntax error." (and an "error:", a "warning:", an
    "unknown command" or a "missing argument") under the statement it
    refused and carries on, so the exit status of the session says
    nothing at all.  The only acceptable output of a statement is
    nothing or an "[edit ...]" marker, and anything else is a line error.

    A statement the device did not echo is a line error as well: the
    outcome of that statement cannot be read, so it cannot be claimed.
    """
    for index, block in enumerate(found, start=1):
        if block is None:
            return index
        for line in block.output:
            if _is_blank(line):
                continue
            if _EDIT_MARKER_RE.match(line.strip()):
                continue
            return index
    return None


def _block_text(blocks: Sequence[_Block], echo: str) -> str:
    """The output of one command of the session, without the CLI markers."""
    for block in blocks:
        if block.echo != echo:
            continue
        lines = list(block.output)
        while lines:
            stripped = lines[-1].strip()
            if stripped and not _EDIT_MARKER_RE.match(stripped):
                break
            lines.pop()
        return "\n".join(lines)
    return ""


def _words(line: str, *, device: bool) -> list[str] | None:
    """The words of one line, or None when the line is not one."""
    try:
        tokens = _tokenize_line(line.strip(), device=device)
    except LintError:
        return None
    return [token.value for token in tokens]


def config_text(out: str, command: str = CONFIG_COMMAND) -> str:
    """The configuration text of a session of the CLI.

    The block between the sentinels: the echo of the command line and
    the next prompt.  The banner and the prompts of the CLI are not part
    of the configuration, so they do not change the hash.

    This is the one normaliser: the candidate of a stage and the running
    configuration of a snapshot are read the same way and hashed the
    same way.
    """
    return _block_text(_split_blocks(out), command)


def _has_control_char(text: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in text)


def _block_has_error(block: _Block) -> bool:
    if _has_control_char(block.echo):
        return True
    for line in block.output:
        stripped = line.strip()
        if stripped == "^" or _STAGE_ERROR_RE.match(stripped) is not None:
            return True
    return False


def parse_stage(out: str, stmts: Sequence[Sequence[str]]) -> StageResult:
    """Read the output of a candidate stage.

    The diff is the text of the compare and the candidate hash is the
    hash of the candidate configuration, so the driver can tell a commit
    that is the candidate from a commit that is not.
    """
    commands = [command_text(tokens) for tokens in stmts]
    blocks = _split_blocks(out)
    found = _statement_blocks(blocks, commands)
    bad_line = _line_error(found)
    candidate_index = next(
        (
            index
            for index, block in enumerate(blocks)
            if block.echo == CANDIDATE_COMMAND
        ),
        len(blocks),
    )
    if bad_line is None and any(
        _block_has_error(block) for block in blocks[: candidate_index + 1]
    ):
        bad_line = len(found) or 1
    diff = _block_text(blocks, "show | compare | no-more")
    candidate = config_text(out, CANDIDATE_COMMAND)
    if bad_line is None and not candidate:
        bad_line = len(found) or 1
    no_changes = not diff.strip()
    return StageResult(
        ok=bad_line is None and not no_changes and bool(candidate),
        diff=diff,
        bad_line=bad_line,
        no_changes=no_changes,
        candidate_hash=config_hash(candidate) if candidate else None,
    )


def parse_apply(out: str, minutes: int, stmts: Sequence[Sequence[str]]) -> str:
    """Read the output of an apply: committed, failed or line_error.

    The commit is proven by two things: the text the device prints when a
    commit went through and the notice of the armed revert, with the
    number of minutes the driver asked for.  A statement the device
    refused is a line error, even when the commit that followed it went
    through: the change on the device is then only part of the change.
    """
    commands = [command_text(tokens) for tokens in stmts]
    blocks = _split_blocks(out)
    if _line_error(_statement_blocks(blocks, commands)) is not None:
        return "line_error"
    if not parse_committed(out):
        return "failed"
    if not _has_rollback_notice(out, minutes):
        return "failed"
    return "committed"


class JunosOps:
    """The Junos operations of the generic driver.

    The revert of a Junos device is native: the apply commits with
    "commit confirmed N", so the device holds the revert and the change
    arrives in the same commit.
    """

    platform = PLATFORM_JUNOS

    def __init__(self) -> None:
        """The operations of a Junos.

        ``expected_hash`` is the hash of the candidate that was staged
        before the apply.  The driver reads the configuration back after
        the commit and compares it with this hash: a commit that is not
        the candidate is a partial or a concurrent change.
        """
        self.expected_hash: str | None = None

    def snapshot(self, run: Run) -> Snapshot:
        """Read the configuration and the commit list in fresh sessions.

        A Junos commits into the saved configuration, so there is no
        unsaved state to report and the reload flag is always true.  A
        revert that is pending shows in the commit list, and the plan
        refuses to run while one is pending.

        The configuration is read with the same normaliser as the
        candidate of a stage, so the hash of the running configuration
        and the hash of the candidate are comparable.
        """
        from ..vendor_change import Snapshot

        config_out = run(config_command())
        pending_out = run(pending_command())
        text = config_text(config_out.stdout) if config_out.status == "ok" else ""
        pending = "unknown"
        if (
            config_out.status == "ok"
            and pending_out.status == "ok"
            and not _refused(pending_out.stdout)
        ):
            pending = "pending" if parse_pending(pending_out.stdout) else "idle"
        return Snapshot(
            text=text,
            base_hash=config_hash(text),
            reload_ok=True,
            saved_clean=True,
            pending=pending,
        )

    def stage(self, run: Run, stmts: list[list[str]]) -> StageResult:
        """Run the candidate session and parse its diff and its errors."""
        output = run(stage_script(stmts))
        return parse_stage(output.stdout, stmts)

    def apply(self, run: Run, stmts: list[list[str]], timeout_s: int) -> str:
        """Stage the change again, then commit it with the revert armed.

        The stage comes first and it is a session of its own: a line the
        device refuses is refused before anything is committed, so
        nothing is on the device and nothing is armed.  The hash of that
        candidate is kept for the driver, which reads the configuration
        back after the commit.

        The commit is the arm: "commit confirmed N" holds the revert on
        the device and puts the change there in the same commit, so
        there is no window in which the change is on the device without a
        revert behind it.
        """
        minutes = minutes_for(timeout_s)
        staged = self.stage(run, stmts)
        if staged.bad_line is not None:
            # the device refused a line: nothing was committed and
            # nothing was armed, so no other session may be sent.
            return "line_error"
        if not staged.ok or staged.candidate_hash is None:
            return "failed"
        self.expected_hash = staged.candidate_hash
        output = run(apply_script(stmts, minutes))
        result = parse_apply(output.stdout, minutes, stmts)
        if result == "line_error":
            # a line failed in the apply session: the commit that
            # followed it holds part of the change, so the revert is
            # taken now.
            self.abort(run)
        return result

    def confirm(self, run: Run) -> bool:
        """Commit the change and take the armed revert away.

        The confirm is a session of its own, and it is true only when
        the device says the commit went through and the commit list
        shows no revert that is pending any more.
        """
        output = run(confirm_script())
        if output.status != "ok" or not parse_committed(output.stdout):
            return False
        check = run(pending_command())
        if check.status != "ok":
            return False
        return not parse_pending(check.stdout)

    def save(self, run: Run) -> bool:
        """A Junos commits into the saved configuration: there is no save."""
        return True

    def abort(self, run: Run) -> bool:
        """Roll the change back: the rollback of the commit before it.

        The commit list is read first, in a session of its own, because
        "rollback 1" is the change of Newton only when the commit of
        Newton is still the top entry of that list and its revert is
        still pending.  Once the armed revert has fired, the rollback of
        the device is a commit of its own, so "rollback 1" would put the
        change back with no revert armed: nothing is rolled back then.

        The abort is true when it rolled the change back and when the
        visible list carries no commit of Newton at all (the device
        rolled the change back by itself).  Every other state is
        ambiguous and the abort says that it does not know: a commit of
        somebody else on top of the change of Newton would be thrown
        away by the rollback, and a change that was confirmed is still
        on the device.
        """
        listed = run(pending_command())
        if listed.status != "ok":
            return False
        decision = abort_decision(parse_commit_list(listed.stdout))
        if decision == ABORT_UNKNOWN:
            return False
        if decision == ABORT_REVERTED:
            return True
        output = run(abort_script())
        if output.status != "ok" or not parse_committed(output.stdout):
            return False
        check = run(pending_command())
        if check.status != "ok":
            return False
        return not parse_pending(check.stdout)

    def pending(self, run: Run) -> str:
        """Read the state of the armed revert from the commit list.

        A commit list that could not be read is not an answer: the state
        of the revert is unknown then, never idle.
        """
        out = run(pending_command())
        if out.status != "ok" or _refused(out.stdout):
            return "unknown"
        return "pending" if parse_pending(out.stdout) else "idle"

    def probe_ping(self, run: Run, host: str) -> bool:
        """Ping a peer and require the packets to come back."""
        out = run(ping_command(host))
        if out.status != "ok":
            return False
        text = out.stdout
        if "3 packets received" in text:
            return True
        return _ZERO_LOSS_RE.search(text) is not None

    def has_line(self, snapshot_text: str, rendered_line: str) -> bool:
        """Compare the configuration and the claim as statements.

        Both sides are read with the tokenizer of this module, so the
        quoting and the spacing do not matter but the words do.  The
        device's own text is read in the read-only mode that takes a
        double quote: the display-set output of a Junos quotes a value
        with double quotes, and the agent's text never does.
        """
        wanted = _words(rendered_line, device=False)
        if not wanted:
            return False
        for line in snapshot_text.splitlines():
            got = _words(line, device=True)
            if got is not None and got == wanted:
                return True
        return False
