"""Vendor lint, tokenizer and VyOS script builders.

The lint, tokenizer, builders and parsers are pure functions and frozen
dataclasses.  ``VyosOps`` is a thin adapter over them; it never opens a
socket or runs a command directly, and the caller owns the transport.

The agent's change text is DATA, never script text.  ``parse_lines`` splits
it into statements of tokens and refuses anything that could add shell or
CLI syntax; ``render_line`` turns tokens back into the canonical text the
owner sees and the plan hashes; the script builders assemble a VyOS script
from re-rendered statements only, so an agent line can never become shell
syntax.  The VyOS path is the one this module has always had; the
routeros path is in ``adapters.routeros_write`` and junos comes
in a later release.

The lint is fail-closed.  Every raw line of the agent's text is bounded
(400 chars) and free of the characters the vendor refuses, so even a
comment line cannot smuggle a metacharacter into the plan.  A token that
carries the marker text ``NEWTON-`` is refused as well: an agent token
that holds a marker could forge one in the device output.

A VyOS statement that the device refuses reports the refusal on stderr
and exits zero, so the exit status of a statement says nothing about a
VyOS error.  The builders therefore write the stderr of every statement
to a file and check that file: any output at all is a line error, and
the wording of the output is never matched.  The exit status of the
statement is kept as well, so a statement that fails in another way
stops the script too.

The file the stderr goes to has to exist before the first statement: a
``mktemp`` that fails leaves the name empty, and then the guard would
never fire.  The scripts therefore check the file right after the
``mktemp`` and stop there.  That error is the session and not a
statement, so it is reported as a refusal of the run.

The early stop of a script is a ``builtin exit``.  In the VyOS
configuration mode a plain ``exit N`` is the configuration-mode command:
it prints "Invalid command: [N]" and the script carries on, so a plain
exit would let the apply go on to the commit-confirm after a line error.
The trailing plain ``exit`` that leaves the configuration mode at the
end of a script is not an early stop and stays as it is.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    from ..vendor_change import Run, Snapshot


PLATFORM_VYOS = "vyos"
PLATFORM_ROUTEROS = "routeros"
PLATFORM_JUNOS = "junos"
SUPPORTED_PLATFORMS = (PLATFORM_VYOS, PLATFORM_ROUTEROS, PLATFORM_JUNOS)

MAX_LINE_CHARS = 400
MAX_STATEMENTS = 200
MIN_MINUTES = 1
MAX_MINUTES = 10

# How much of the agent's own text a lint message may echo.  Longer text
# is cut to this many characters and an ellipsis is added.
MAX_AGENT_TEXT_CHARS = 20

# Marker text Newton puts in device output.  A token that carries it could
# forge a marker, so any token with this substring is refused.
RESERVED_MARKER_TEXT = "NEWTON-"

ALLOWED_VERBS = ("set", "delete", "comment")

# A bare word is a path element or a value without a space.
BARE_WORD_RE = re.compile(r"[A-Za-z0-9_./:@%+=,-]+")
# The content of a single-quoted value may hold spaces, nothing else.
QUOTED_CONTENT_RE = re.compile(r"[A-Za-z0-9 _./:@%+=,-]*")
HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}")

# Characters the vendor refuses anywhere in the raw text.  Double quotes
# are in the set: values are quoted with single quotes only.
FORBIDDEN_CHARS = frozenset(";|&$`\\<>(){}[]!*?\"")
CONTROL_CHARS = frozenset(chr(code) for code in range(0x20)) | {chr(0x7F)}

# Refused outright, whatever the verb: these paths touch the login users or
# the commit-confirm machinery itself.
REFUSED_PATH_PREFIXES = (
    ("system", "login"),
    ("system", "config-management"),
)
# Refused by default because they widen access.  A later release may add an
# explicit allow flag; this release has none.
REFUSED_SERVICE_PREFIXES = (
    ("service", "telnet"),
    ("service", "http"),
    ("service", "https"),
    ("service", "ssh"),
    ("service", "snmp"),
    ("service", "tftp-server"),
    ("service", "ftp"),
)

_VBASH_REMOTE = "vbash -s"
_SCRIPT_TEMPLATE = "source /opt/vyatta/etc/functions/script-template"
_LINE_ERROR_RE = re.compile(r"NEWTON-LINE-ERROR (\d+)")

# The file every statement writes its stderr to.  VyOS reports a refused
# path on stderr and still exits zero, so the exit status of a statement
# says nothing at all: the stderr file is the evidence of a VyOS error.
# The exit status is kept as well, because a statement can fail in
# another way, and a failure that is not on stderr is still a failure.
_ERR_FILE_OPEN = "NEWTON_ERR=$(mktemp)"
_ERR_FILE_CLEAN = 'rm -f "$NEWTON_ERR"'
# The check that the error file really exists.  ``mktemp`` can fail (no
# temporary space, a read-only /tmp) and then NEWTON_ERR is empty: every
# statement would write its stderr into a file that is not there, the
# guard would never fire and the apply would go on to the commit-confirm.
# The line number of this error is 0: it is not a statement of the
# change, it is the session that could not be prepared.
_ERR_FILE_GUARD = (
    'if [ -z "$NEWTON_ERR" ] || [ ! -w "$NEWTON_ERR" ]; then '
    'echo "NEWTON-LINE-ERROR 0"; builtin exit 1; fi'
)

BEGIN_DIFF = "NEWTON-BEGIN-DIFF"
END_DIFF = "NEWTON-END-DIFF"
BEGIN_SAVED = "NEWTON-BEGIN-SAVED"
END_SAVED = "NEWTON-END-SAVED"
COMMITTED_MARKER = "NEWTON-COMMITTED rc=0"
LINE_ERROR_MARKER = "NEWTON-LINE-ERROR"
# The refusal of a session that could not be prepared at all.  It is not
# a statement of the change that failed, so the message says what
# happened instead of blaming a statement.
SESSION_ERROR_REFUSAL = "could not prepare the session"
SAVED_OK_MARKER = "NEWTON-SAVED rc=0"
SAVED_NO_CHANGES = "No changes between working and saved configurations"
ACTIVE_NO_CHANGES = "No changes between working and active configurations"
RELOAD_MODE_LINE = "set system config-management commit-confirm action 'reload'"


class LintError(ValueError):
    """The agent's change text breaks the vendor lint rules.

    The message is a short reason.  It never echoes more than 20
    characters of the offending text.
    """


@dataclass(frozen=True)
class SessionSpec:
    """One remote session: the exact remote command and the script on stdin."""

    remote: str
    stdin: str


@dataclass(frozen=True)
class StageResult:
    """What a candidate (dry run) stage produced.

    ``no_changes`` says the candidate diff was empty: the statements
    changed nothing, so there is no change to plan.

    ``candidate_hash`` is the hash of the candidate configuration, for the
    vendors that have one (Junos): the driver reads the configuration
    back after the commit and compares it with this hash, so a commit
    that is not the candidate that was staged is a partial or a
    concurrent change.  It is None for the vendors that do not have one.
    """

    ok: bool
    diff: str
    bad_line: int | None
    no_changes: bool = False
    candidate_hash: str | None = None


@dataclass(frozen=True)
class _Token:
    """One token of a statement and whether it was quoted."""

    value: str
    quoted: bool


def _require_platform(platform: str) -> None:
    """Refuse a platform this release does not implement."""
    if platform not in SUPPORTED_PLATFORMS:
        raise ValueError(
            f"unsupported platform {platform!r}: "
            "vyos, routeros and junos in this release"
        )


def _short_agent_text(text: str) -> str:
    """Return at most 20 characters of agent text, then an ellipsis.

    Every lint message that quotes the agent's text goes through here, so
    a long verb, path, character or service cannot put a long string into
    an error message.
    """
    if len(text) <= MAX_AGENT_TEXT_CHARS:
        return text
    return text[:MAX_AGENT_TEXT_CHARS] + "..."


def _check_token_text(text: str) -> None:
    """Refuse a token that carries the reserved marker text."""
    if RESERVED_MARKER_TEXT in text:
        raise LintError("reserved marker text")


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


def _tokenize_line(line: str) -> list[_Token]:
    """Split one statement into tokens; refuse anything malformed."""
    tokens: list[_Token] = []
    index = 0
    length = len(line)
    while index < length:
        if line[index] == " ":
            index += 1
            continue
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
            tokens.append(_Token(content, True))
            index = end + 1
        else:
            end = index
            while end < length and line[end] not in " '":
                end += 1
            word = line[index:end]
            _check_token_text(word)
            if not BARE_WORD_RE.fullmatch(word):
                raise LintError("token has refused characters")
            tokens.append(_Token(word, False))
            index = end
        if index < length and line[index] != " ":
            raise LintError("missing space after token")
    return tokens


def _check_statement(values: Sequence[str]) -> None:
    """Refuse a statement whose verb or path the vendor refuses.

    The verb check comes first so a refused verb is named, and the path
    check walks the words after it.  The messages quote the agent's own
    text, so it is cut to 20 characters before it goes in.
    """
    if not values:
        raise LintError("empty statement")
    verb = values[0]
    if verb not in ALLOWED_VERBS:
        raise LintError(f"refused verb {_short_agent_text(verb)!r}")
    if len(values) < 2:
        raise LintError("statement needs a path word after the verb")
    path = list(values[1:])
    path_text = " ".join(path)
    for prefix in REFUSED_PATH_PREFIXES:
        if path[: len(prefix)] == list(prefix):
            raise LintError(f"refused path {_short_agent_text(path_text)!r}")
    for prefix in REFUSED_SERVICE_PREFIXES:
        if path[: len(prefix)] == list(prefix):
            raise LintError(f"refused service {_short_agent_text(path_text)!r}")


def parse_lines(platform: str, text: str) -> list[list[str]]:
    """Split the agent's change text into statements, each a list of tokens.

    Raises LintError for anything the vendor refuses: a metacharacter, a
    control or non-ascii character, a line over 400 characters, more than
    200 statements, a reserved verb, a refused path prefix, a statement
    without a path word, a comment without a quoted last token, an empty
    quoted value (``''``) and any token that carries the reserved marker
    text ``NEWTON-``.

    The platform decides the rules: the VyOS path below is the one this
    module has always had, the routeros path is in
    ``adapters.routeros_write`` and the junos path is in
    ``adapters.junos_write``.
    """
    _require_platform(platform)
    if platform == PLATFORM_ROUTEROS:
        from .routeros_write import parse_lines as routeros_parse_lines

        return routeros_parse_lines(text)
    if platform == PLATFORM_JUNOS:
        from .junos_write import parse_lines as junos_parse_lines

        return junos_parse_lines(text)
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
        _check_statement([token.value for token in tokens])
        if tokens[0].value == "comment" and not tokens[-1].quoted:
            raise LintError("comment needs a quoted last token")
        statements.append([token.value for token in tokens])
        if len(statements) > MAX_STATEMENTS:
            raise LintError(f"too many statements (max {MAX_STATEMENTS})")
    return statements


def render_line(platform: str, tokens: Sequence[str]) -> str:
    """Return the canonical text of one statement.

    A bare word is re-emitted as it is; a value with a space comes back in
    single quotes.  What comes out is what the owner sees, what the plan
    hashes and what the tokenizer accepts again, so
    ``parse_lines(platform, render_line(platform, tokens))`` round-trips.

    An empty value is refused, so an empty quoted value (``''``) never comes
    back; and a token that carries the reserved marker text ``NEWTON-`` is
    refused here too, so the renderer cannot become a way round the lint.

    The platform decides the rules: the VyOS path below is the one this
    module has always had, the routeros path is in
    ``adapters.routeros_write`` and the junos path is in
    ``adapters.junos_write``.
    """
    _require_platform(platform)
    if platform == PLATFORM_ROUTEROS:
        from .routeros_write import render_line as routeros_render_line

        return routeros_render_line(tokens)
    if platform == PLATFORM_JUNOS:
        from .junos_write import render_line as junos_render_line

        return junos_render_line(tokens)
    parts: list[str] = []
    for token in tokens:
        if not isinstance(token, str) or not token:
            raise LintError("empty token")
        _check_token_text(token)
        if " " in token:
            if not QUOTED_CONTENT_RE.fullmatch(token):
                raise LintError("token has refused characters")
            parts.append(f"'{token}'")
        else:
            if not BARE_WORD_RE.fullmatch(token):
                raise LintError("token has refused characters")
            parts.append(token)
    return " ".join(parts)


def _statement_tokens(line: str) -> list[str] | None:
    """The tokens of one statement, or None when the line is not one.

    The vendor's own tokenizer decides what a statement is: a line it
    refuses (a banner, a comment, a line with a character the vendor does
    not accept) is not a statement, and no claim is ever satisfied by it.
    """
    try:
        tokens = _tokenize_line(line.strip())
    except LintError:
        return None
    return [token.value for token in tokens]


def minutes_for(timeout_s: int) -> int:
    """Return the commit-confirm minutes for a timeout in seconds.

    Rounded up to the minute and clamped to 1..10.  Zero or a negative
    timeout is refused, and a bool is not a timeout.
    """
    if isinstance(timeout_s, bool):
        raise TypeError("timeout_s must be an int, not a bool")
    if not isinstance(timeout_s, int):
        raise TypeError("timeout_s must be an int")
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")
    minutes = -(-timeout_s // 60)
    return max(MIN_MINUTES, min(MAX_MINUTES, minutes))


def _statement_lines(stmts: Iterable[Sequence[str]]) -> list[str]:
    """Render each statement as a guarded line of the script.

    The statement is re-rendered from its tokens, never copied from the
    agent's text, and it is the only thing in the line that comes from the
    agent.

    A VyOS statement that the device refuses reports the refusal on
    stderr and still exits zero, so a guard that reads the exit status
    alone never fires.  Every statement therefore writes its stderr to the
    file ``NEWTON_ERR`` and the next line checks that file: any output at
    all is a line error, and the script stops there.  The check is on the
    file and never on the wording of the output, so no device text is
    matched.

    The exit status of the statement is kept as well, in ``NEWTON_RC``:
    a statement that fails with a non-zero status and an empty stderr
    file is a failure too, and the guard fires on either leg.

    The stop is a ``builtin exit 1``: in the configuration mode a plain
    ``exit 1`` is the configuration-mode command, it prints "Invalid
    command" and the script carries on, so it would not stop the script
    and the apply would go on to the commit-confirm.
    """
    lines: list[str] = []
    for index, tokens in enumerate(stmts, start=1):
        values = list(tokens)
        _check_statement(values)
        rendered = render_line(PLATFORM_VYOS, values)
        lines.append(f'{rendered} 2>"$NEWTON_ERR"; NEWTON_RC=$?')
        lines.append(
            f'if [ "$NEWTON_RC" -ne 0 ] || [ -s "$NEWTON_ERR" ]; then '
            f'echo "NEWTON-LINE-ERROR {index}"; '
            f'discard; rm -f "$NEWTON_ERR"; builtin exit 1; fi'
        )
    return lines


def stage_script(stmts: Iterable[Sequence[str]]) -> SessionSpec:
    """Return the candidate (dry run) script: compare, then discard."""
    lines = [
        _SCRIPT_TEMPLATE,
        "configure",
        _ERR_FILE_OPEN,
        _ERR_FILE_GUARD,
        *_statement_lines(stmts),
        f'echo "{BEGIN_DIFF}"',
        "compare",
        f'echo "{END_DIFF}"',
        _ERR_FILE_CLEAN,
        "discard",
        "exit",
    ]
    return SessionSpec(remote=_VBASH_REMOTE, stdin="\n".join(lines) + "\n")


def apply_script(stmts: Iterable[Sequence[str]], minutes: int) -> SessionSpec:
    """Return the apply script: the statements, then the armed commit.

    ``no-prompt`` is mandatory: VyOS blocks forever on a commit-confirm
    without it, and the session would hang with the revert pending.
    """
    if isinstance(minutes, bool) or not isinstance(minutes, int):
        raise TypeError("minutes must be an int")
    if not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise ValueError(f"minutes must be {MIN_MINUTES}..{MAX_MINUTES}")
    lines = [
        _SCRIPT_TEMPLATE,
        "configure",
        _ERR_FILE_OPEN,
        _ERR_FILE_GUARD,
        *_statement_lines(stmts),
        "compare",
        f"commit-confirm {minutes} no-prompt",
        'echo "NEWTON-COMMITTED rc=$?"',
        _ERR_FILE_CLEAN,
        "exit",
    ]
    return SessionSpec(remote=_VBASH_REMOTE, stdin="\n".join(lines) + "\n")


def confirm_script() -> SessionSpec:
    """Return the confirm script: confirm, then report the rc."""
    lines = [
        _SCRIPT_TEMPLATE,
        "confirm",
        'echo "NEWTON-CONFIRMED rc=$?"',
        "exit",
    ]
    return SessionSpec(remote=_VBASH_REMOTE, stdin="\n".join(lines) + "\n")


def abort_script() -> SessionSpec:
    """Return the abort script: revert first, stop the timer only then.

    The timer is the backstop, so it is stopped only after the revert
    returned 0.  A failed revert keeps the timer running.
    """
    lines = [
        _SCRIPT_TEMPLATE,
        'sudo sg vyattacfg "/usr/bin/config-mgmt revert_soft"',
        "NEWTON_ABORT_RC=$?",
        'if [ "$NEWTON_ABORT_RC" -eq 0 ]; then',
        "  sudo systemctl stop commit-confirm.timer",
        "fi",
        'echo "NEWTON-ABORT revert_rc=$NEWTON_ABORT_RC"',
        "exit",
    ]
    return SessionSpec(remote=_VBASH_REMOTE, stdin="\n".join(lines) + "\n")


def save_script() -> SessionSpec:
    """Return the save script: save the running config, then report the rc.

    The save runs in configuration mode, where VyOS writes the running
    configuration to the saved one.  The rc of the save itself is echoed
    on a line of its own, so the caller can tell a saved configuration
    from a failed save.
    """
    lines = [
        _SCRIPT_TEMPLATE,
        "configure",
        "save",
        'echo "NEWTON-SAVED rc=$?"',
        "exit",
    ]
    return SessionSpec(remote=_VBASH_REMOTE, stdin="\n".join(lines) + "\n")


def status_command() -> SessionSpec:
    """Return the command that reads the pending-revert timer state."""
    return SessionSpec(remote="systemctl is-active commit-confirm.timer", stdin="")


def saved_check_script() -> SessionSpec:
    """Return the script that compares the running config with the saved one."""
    lines = [
        _SCRIPT_TEMPLATE,
        "configure",
        f'echo "{BEGIN_SAVED}"',
        "compare saved",
        f'echo "{END_SAVED}"',
        "exit",
    ]
    return SessionSpec(remote=_VBASH_REMOTE, stdin="\n".join(lines) + "\n")


def read_config_command() -> SessionSpec:
    """Return the command that reads the running config as commands."""
    return SessionSpec(
        remote="/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands",
        stdin="",
    )


def ping_command(host: str) -> SessionSpec:
    """Return the command that pings a peer, host charset bounded."""
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise LintError("refused ping host")
    return SessionSpec(remote=f"ping -c 2 -W 2 -- {host}", stdin="")


def _marker_index(lines: Sequence[str], marker: str) -> int | None:
    """Return the index of the last line that is exactly the marker.

    A marker echoed inside device output is not at the start of a line of
    its own, so it does not count.  When a marker appears more than once
    the last occurrence wins.
    """
    found: int | None = None
    for position, line in enumerate(lines):
        if line.rstrip() == marker:
            found = position
    return found


def _between(lines: Sequence[str], begin: str, end: str) -> str | None:
    """Return the text between the last begin and end markers."""
    start = _marker_index(lines, begin)
    stop = _marker_index(lines, end)
    if start is None or stop is None or stop <= start:
        return None
    return "\n".join(lines[start + 1 : stop])


def _no_changes(text: str) -> bool:
    """True when the diff says there is nothing to change.

    The sentence has to be a line of its own: a description that quotes
    it is a change, not an empty diff.
    """
    for line in text.splitlines():
        if line.strip().rstrip(".") == ACTIVE_NO_CHANGES:
            return True
    return False


def _session_refusal() -> NoReturn:
    """Refuse the run: the session itself could not be prepared.

    The line number of the error is 0 and not the number of a statement:
    the error file could not be made, so no statement ran at all.  The
    refusal is not about a statement the device rejected, and the message
    says so.
    """
    from ..vendor_change import VendorRefusal

    raise VendorRefusal(SESSION_ERROR_REFUSAL)


def _session_error(lines: Sequence[str]) -> bool:
    """Does the output carry the error of a session that was not prepared?"""
    for line in lines:
        match = _LINE_ERROR_RE.fullmatch(line.rstrip())
        if match and int(match.group(1)) == 0:
            return True
    return False


def parse_stage(out: str) -> StageResult:
    """Read the output of a candidate stage.

    The diff is only the text between the markers; a line error names the
    statement that failed.  A diff that says there is nothing to change is
    not a candidate: ``no_changes`` says so and the plan is refused.

    A session that could not be prepared (the error file was not there)
    is a refusal of the run, not a statement that failed.
    """
    lines = out.splitlines()
    if _session_error(lines):
        _session_refusal()
    bad_line: int | None = None
    for line in lines:
        match = _LINE_ERROR_RE.fullmatch(line.rstrip())
        if match:
            bad_line = int(match.group(1))
            break
    diff = _between(lines, BEGIN_DIFF, END_DIFF)
    if diff is None:
        return StageResult(ok=False, diff="", bad_line=bad_line)
    no_changes = _no_changes(diff)
    return StageResult(
        ok=bad_line is None and not no_changes,
        diff=diff,
        bad_line=bad_line,
        no_changes=no_changes,
    )


def parse_apply(out: str) -> str:
    """Read the output of an apply: committed, failed or line_error.

    Exactly one committed marker with rc 0 means committed.  A marker that
    the device echoed inside a description is not at the start of a line
    of its own, so it does not count.

    A line error next to a committed marker is a failure: the device
    printed both, so the outcome of the change is not the clean "nothing
    was committed" of a line error alone.

    A session that could not be prepared is a refusal of the run.
    """
    lines = out.splitlines()
    if _session_error(lines):
        _session_refusal()
    has_line_error = any(
        _LINE_ERROR_RE.fullmatch(line.rstrip()) for line in lines
    )
    committed = [line for line in lines if line.rstrip() == COMMITTED_MARKER]
    if has_line_error and committed:
        return "failed"
    if has_line_error:
        return "line_error"
    if len(committed) == 1:
        return "committed"
    return "failed"


def parse_saved_ok(out: str) -> bool:
    """True when the device printed exactly one saved marker with rc zero.

    The marker counts only as a line of its own: a marker inside a
    description, a prefixed marker, a marker with another rc or a marker
    with extra text does not count, and two marker lines are not a save
    either.
    """
    lines = out.splitlines()
    markers = [line for line in lines if line.rstrip() == SAVED_OK_MARKER]
    return len(markers) == 1


def parse_saved(out: str) -> bool:
    """True when the saved check found no change between working and saved."""
    lines = out.splitlines()
    text = _between(lines, BEGIN_SAVED, END_SAVED)
    if text is None:
        return False
    return SAVED_NO_CHANGES in text


def parse_reload_mode(config_text: str) -> bool:
    """True when the config asks the revert to reload instead of reboot.

    The line must match exactly: nothing is stripped, so an indented line
    and a line with trailing space do not count.
    """
    for line in config_text.splitlines():
        if line == RELOAD_MODE_LINE:
            return True
    return False


def parse_timer(out: str) -> str:
    """Read the timer state: pending, idle or unknown."""
    text = out.strip()
    if text == "active":
        return "pending"
    if text == "inactive":
        return "idle"
    return "unknown"


class VyosOps:
    """VyOS operations built from the pure builders and parsers above."""

    platform = PLATFORM_VYOS

    def snapshot(self, run: Run) -> Snapshot:
        """Read the running config, saved state and timer in fresh sessions."""
        from ..vendor_change import Snapshot

        config_out = run(read_config_command())
        saved_out = run(saved_check_script())
        timer_out = run(status_command())
        text = config_out.stdout
        return Snapshot(
            text=text,
            base_hash=hashlib.sha256(text.encode()).hexdigest(),
            reload_ok=parse_reload_mode(text),
            saved_clean=parse_saved(saved_out.stdout),
            pending=parse_timer(timer_out.stdout),
        )

    def stage(self, run: Run, stmts: list[list[str]]) -> StageResult:
        """Run the candidate script and parse its diff or rejected line."""
        output = run(stage_script(stmts))
        return parse_stage(output.stdout)

    def apply(self, run: Run, stmts: list[list[str]], timeout_s: int) -> str:
        """Apply the statements with the VyOS commit-confirm revert armed."""
        output = run(apply_script(stmts, minutes_for(timeout_s)))
        return parse_apply(output.stdout)

    def confirm(self, run: Run) -> bool:
        """Confirm the pending change only when the device reports rc zero."""
        output = run(confirm_script())
        return (
            output.status == "ok"
            and output.exit_code == 0
            and any(
                line.rstrip() == "NEWTON-CONFIRMED rc=0"
                for line in output.stdout.splitlines()
            )
        )

    def save(self, run: Run) -> bool:
        """Save the running configuration and report the device's own rc.

        The marker carries the rc of the save itself, so the session exit
        code is not what decides the outcome.
        """
        output = run(save_script())
        return output.status == "ok" and parse_saved_ok(output.stdout)

    def abort(self, run: Run) -> bool:
        """Revert first and report success only when the revert returned zero."""
        output = run(abort_script())
        return (
            output.status == "ok"
            and output.exit_code == 0
            and any(
                line.rstrip() == "NEWTON-ABORT revert_rc=0"
                for line in output.stdout.splitlines()
            )
        )

    def pending(self, run: Run) -> str:
        """Read the device-side commit-confirm timer state."""
        output = run(status_command())
        if output.status != "ok":
            return "unknown"
        return parse_timer(output.stdout)

    def probe_ping(self, run: Run, host: str) -> bool:
        """Ping a host in a fresh session and require a zero exit code."""
        output = run(ping_command(host))
        return output.status == "ok" and output.exit_code == 0

    def has_line(self, snapshot_text: str, rendered_line: str) -> bool:
        """Compare the configuration and the claim as statements.

        Both sides are read with the vendor's own tokenizer, so the
        quoting and the spacing do not matter but the words do: the claim
        ``set a 'b c'`` is the path ``a`` with the value ``b c``, and the
        configuration line ``set a b 'c'`` is the path ``a b`` with the
        value ``c``.  They are different statements, so one does not
        satisfy the other.
        """
        wanted = _statement_tokens(rendered_line)
        if not wanted:
            return False
        for line in snapshot_text.splitlines():
            if _statement_tokens(line) == wanted:
                return True
        return False
