"""the owner script -- one fixed template, rendered for one plan.

ADR-021 point 7, word for word: the owner approves the EXACT bytes of
the script, so the bytes must be the same every time for the same
plan, and nothing from the router or from the agent may be able to
become shell code.

There is one template, ``owner-v1``, and it renders both the apply
script and the restore script.  The script arrives on the router over
``sh -s`` stdin, so:

  * every command carries ``</dev/null``: a command that read stdin
    would eat the rest of the script;
  * there is exactly ONE state-changing call, the ``uci apply`` with
    the router's own rollback armed.  Before that line only tmpfs is
    written (``$W`` and ``/var/run/rpcd/uci-$SID``), so a script that
    dies, is killed or loses ssh leaves ``/etc/config`` untouched;
  * the script never confirms, never destroys the session (that would
    cancel the rollback) and never prints the session id.  The session
    dies by timeout at ``WINDOW + 120``;
  * every value and every key sits inside single quotes, and the value
    grammar forbids the quote itself, so nothing can become shell
    code.

``render_script`` is deterministic: LF only, a final newline, no
timestamp, no host name, no agent text and no explanation.  The parse
round trip (``parse_script(render_script(p)) == p``) is the proof that
the bytes say what Newton meant, and a one-byte edit either refuses to
parse or parses into a different plan.

This module is pure: it renders and parses text.  It never touches a
router, a file or the network.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Callable, Sequence

from . import policy
from .owner_ops import check_value


class ScriptError(Exception):
    """A refusal of an owner script.

    The message names a line or a key, never a value: a value can hold
    a secret, and a value that came from the router is untrusted text.
    """


#: The name of the template.  A template edit changes this name and the
#: pin below; the pin is what makes the edit a reviewed diff.
TEMPLATE_NAME = "owner-v1"

#: The kinds of script.
KIND_APPLY = "apply"
KIND_RESTORE = "restore"
KINDS: tuple[str, ...] = (KIND_APPLY, KIND_RESTORE)

#: The device name the header may carry.
DEVICE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

#: A plan id.
PLAN_ID_RE = re.compile(r"^[0-9a-f]{32}$")

#: The window bounds (the design's rule 9).
WINDOW_MIN_S = 120
WINDOW_MAX_S = 600

#: The verbs a stage line may carry.
STAGE_VERBS: tuple[str, ...] = ("set", "add_list", "del_list", "delete", "reorder")


# ---- the template ----------------------------------------------------------

#: The lines that read the age of the newest undo file.  They are
#: fixed text: no value of the plan ever enters them.  A restart of the
#: router's web service forgets the window but leaves the undo file
#: behind for good (measured, a4m-02), so an undo file that is older
#: than 15 minutes is a leftover and not a live window.  The window is
#: still refused; the message says how the owner gets rid of the file.
UNDO_LINES: tuple[str, ...] = (
    "undo_now=$(date +%s 2>/dev/null </dev/null) || undo_now=''",
    "undo_newest=0",
    "for undo_f in /var/run/rpcd/snapshot-files/*; do",
    '  [ -f "$undo_f" ] || continue',
    "  undo_m=$(stat -c %Y \"$undo_f\" 2>/dev/null </dev/null) || undo_m=''",
    '  case "$undo_m" in',
    "    '' | *[!0-9]*) continue ;;",
    "  esac",
    '  if [ "$undo_m" -gt "$undo_newest" ]; then undo_newest=$undo_m; fi',
    "done",
    "# shellcheck disable=SC2217",
    'if [ -n "$(ls -A /var/run/rpcd/snapshot-files 2>/dev/null </dev/null)" ]; then',
    '  if [ -n "$undo_now" ] && [ "$undo_newest" -gt 0 ]; then',
    '    undo_age=$((undo_now - undo_newest))',
    '    if [ "$undo_age" -ge 900 ]; then',
    '      undo_mins=$((undo_age / 60))',
    '      if [ "$undo_mins" -ge 1440 ]; then',
    '        undo_days=$((undo_mins / 1440))',
    '        if [ "$undo_days" -eq 1 ]; then undo_text="1 day"; else undo_text="$undo_days days"; fi',
    '      elif [ "$undo_mins" -ge 60 ]; then',
    '        undo_hours=$((undo_mins / 60))',
    '        if [ "$undo_hours" -eq 1 ]; then undo_text="1 hour"; else undo_text="$undo_hours hours"; fi',
    "      else",
    '        if [ "$undo_mins" -eq 1 ]; then undo_text="1 minute"; else undo_text="$undo_mins minutes"; fi',
    "      fi",
    '      die "the router has a leftover undo file from $undo_text ago (its web service restarted during a change). If nobody is changing the router right now, reboot it, or as root run: rm -rf /var/run/rpcd/snapshot-files"',
    "    fi",
    "  fi",
    '  die "another change is waiting for confirmation (LuCI or Newton)"',
    "fi",
)


#: The template, as an ordered list of lines.  A line that is a marker
#: (``@@name@@``) is the one place a value from the plan enters the
#: script; every other line is fixed text.  The template IS the
#: skeleton: every variable line format is replaced by its marker, so
#: the sha256 of this text is the pin of the template.
TEMPLATE_LINES: tuple[str, ...] = (
    "#!/bin/sh",
    "@@kind_line@@",
    "@@plan_line@@",
    "# Runs as root on your router, sent by newton-router-setup over your own admin login.",
    "@@purpose_line@@",
    "@@reboot_line@@",
    "@@touches_line@@",
    "@@undo_line@@",
    "set -u",
    "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH",
    "LC_ALL=C; export LC_ALL",
    "umask 077",
    "@@plan_var@@",
    "@@window_var@@",
    'die() { echo "NEWTON-STOP: $*"; exit 1; }',
    '[ "$(id -u </dev/null)" = 0 ] || die "this must run as root"',
    'echo "NEWTON-APPLYING plan=$PLAN"',
    'W=$(mktemp -d /tmp/newton-owner.XXXXXX </dev/null) || die "no private directory"',
    "trap 'rm -rf \"$W\"' EXIT",
    "trap 'rm -rf \"$W\"; exit 1' HUP INT TERM",
    '[ -z "$(uci changes </dev/null)" ] || die "the router has uncommitted changes"',
    *UNDO_LINES,
    'if [ -d /var/run/rpcd/snapshot-files ]; then echo "NEWTON-NOTE: the router has an empty leftover from a refused change (/var/run/rpcd/snapshot-files); it does not block Newton"; fi',
    'want() { got=$(uci -q get "$1" </dev/null) && [ "$got" = "$2" ] || die "the router changed since the plan: $1"; }',
    'absent() { if uci -q get "$1" >/dev/null </dev/null; then die "the router changed since the plan: $1"; fi; }',
    "@@preconditions@@",
    'echo "NEWTON-CHECKED plan=$PLAN"',
    'SID=$(ubus call session create "{\\"timeout\\":$((WINDOW + 120))}" </dev/null | jsonfilter -e \'@.ubus_rpc_session\')',
    "printf '%s' \"$SID\" | grep -Eq '^[0-9a-f]{32}$' || die \"could not open a session\"",
    'ubus call session grant "{\\"ubus_rpc_session\\":\\"$SID\\",\\"scope\\":\\"uci\\",\\"objects\\":[[\\"*\\",\\"read\\"],[\\"*\\",\\"write\\"]]}" </dev/null >/dev/null || die "could not open a session"',
    'ubus call session grant "{\\"ubus_rpc_session\\":\\"$SID\\",\\"scope\\":\\"ubus\\",\\"objects\\":[[\\"uci\\",\\"confirm\\"]]}" </dev/null >/dev/null || die "could not open a session"',
    'D="/var/run/rpcd/uci-$SID"',
    'mkdir -p "$D" || die "no staging directory"',
    'stage() { "$@" </dev/null >/dev/null 2>"$W/err" && [ ! -s "$W/err" ] || die "the router refused a change; nothing was applied"; }',
    "@@stages@@",
    '[ -n "$(uci -P "$D" changes </dev/null)" ] || die "nothing to apply"',
    'echo "NEWTON-STAGED plan=$PLAN"',
    "trap '' HUP INT TERM",
    'ubus call uci apply "{\\"ubus_rpc_session\\":\\"$SID\\",\\"rollback\\":true,\\"timeout\\":$WINDOW}" </dev/null >/dev/null || die "the router refused the apply; nothing changed"',
    'echo "NEWTON-APPLIED plan=$PLAN window=$WINDOW session=$SID"',
)

#: The template skeleton: the sha256 of this text is the pin of the
#: template.  A template edit changes it, and the test that checks the
#: pin is what makes that edit a reviewed diff.
TEMPLATE_SKELETON = "\n".join(TEMPLATE_LINES) + "\n"

#: The sha256 of the template skeleton.  Changing the template means
#: changing this number in the same review.
TEMPLATE_SHA256 = "5aaed5aeb9277e2203388fa44f55032f252c50cad76cc27bbd2e92d28701486f"


def template_sha256() -> str:
    """The sha256 of the template skeleton that is in this source."""
    return hashlib.sha256(TEMPLATE_SKELETON.encode("utf-8")).hexdigest()


def script_sha256(data: bytes) -> str:
    """The sha256 of a rendered script."""
    if not isinstance(data, (bytes, bytearray)):
        raise ScriptError("the script must be bytes")
    return hashlib.sha256(bytes(data)).hexdigest()


# ---- the plan of a script --------------------------------------------------


@dataclass(frozen=True)
class ScriptPlan:
    """What a rendered script says.

    ``sid`` is the plan id the script belongs to (the apply plan id for
    an apply script, the restore plan id for a restore script).
    ``restore_sid`` is the restore plan id an apply script names, and
    ``restore_of`` is the apply plan id a restore script names.  The
    ``ops`` are ``(verb, key, value)`` triples; a value of None means
    the op writes no value.
    """

    sid: str
    kind: str
    device: str
    window: int
    restore_sid: str = ""
    restore_of: str = ""
    preconditions: tuple[tuple[str, str | None], ...] = ()
    ops: tuple[tuple[str, str, str | None], ...] = ()


def touches_of(ops: Sequence[tuple[str, str, str | None]]) -> tuple[str, ...]:
    """The paths the ops touch, in the order they first appear."""
    seen: list[str] = []
    for _verb, key, _value in ops:
        if key not in seen:
            seen.append(key)
    return tuple(seen)


def _check_plan(plan: ScriptPlan) -> None:
    if not isinstance(plan, ScriptPlan):
        raise ScriptError("the script plan must be a ScriptPlan")
    if plan.kind not in KINDS:
        raise ScriptError("the script kind must be apply or restore")
    if PLAN_ID_RE.fullmatch(plan.sid or "") is None:
        raise ScriptError("the script plan id must be 32 lowercase hex characters")
    if DEVICE_RE.fullmatch(plan.device or "") is None:
        raise ScriptError("the script device name fails the grammar")
    if (
        isinstance(plan.window, bool)
        or not isinstance(plan.window, int)
        or not WINDOW_MIN_S <= plan.window <= WINDOW_MAX_S
    ):
        raise ScriptError(
            "the script window must be {0}..{1} seconds".format(
                WINDOW_MIN_S, WINDOW_MAX_S
            )
        )
    if plan.kind == KIND_APPLY:
        if PLAN_ID_RE.fullmatch(plan.restore_sid or "") is None:
            raise ScriptError("an apply script must name its restore plan id")
        if plan.restore_of:
            raise ScriptError("an apply script does not restore anything")
    else:
        if PLAN_ID_RE.fullmatch(plan.restore_of or "") is None:
            raise ScriptError("a restore script must name the plan it restores")
        if plan.restore_sid:
            raise ScriptError("a restore script has no restore plan id")
    for key, value in plan.preconditions:
        _check_key(key)
        if value is not None and not check_value(value):
            raise ScriptError(
                "the precondition of {0} cannot be written safely".format(key)
            )
    if not plan.ops:
        raise ScriptError("a script must stage at least one change")
    for verb, key, value in plan.ops:
        if verb not in STAGE_VERBS:
            raise ScriptError(
                "{0} is not a verb an owner script may carry".format(verb)
            )
        _check_key(key)
        if value is not None and not check_value(value):
            raise ScriptError(
                "the value of {0} cannot be written safely".format(key)
            )


def _check_key(key: str) -> None:
    """A key of the form ``config.section`` or ``config.section.option``."""
    if not isinstance(key, str):
        raise ScriptError("a script key must be text")
    parts = key.split(".")
    if len(parts) not in (2, 3):
        raise ScriptError("{0} is not a uci path".format(key))
    if policy.CONFIG_NAME_RE.fullmatch(parts[0]) is None:
        raise ScriptError("{0} is not a uci path".format(key))
    if policy.SECTION_NAME_RE.fullmatch(parts[1]) is None:
        raise ScriptError("{0} is not a uci path".format(key))
    if len(parts) == 3 and policy.OPTION_NAME_RE.fullmatch(parts[2]) is None:
        raise ScriptError("{0} is not a uci path".format(key))


# ---- the rendering ---------------------------------------------------------


def _kind_line(plan: ScriptPlan) -> list[str]:
    return [
        "# Newton owner script. Template {0}. Kind {1}.".format(
            TEMPLATE_NAME, plan.kind
        )
    ]


def _plan_line(plan: ScriptPlan) -> list[str]:
    return ["# Plan {0} for device {1}.".format(plan.sid, plan.device)]


def _purpose_line(plan: ScriptPlan) -> list[str]:
    if plan.kind == KIND_APPLY:
        return [
            "# It changes /etc/config only through one `uci apply`, with the "
            "router's own undo timer of {0} s.".format(plan.window)
        ]
    return [
        "# It restores what plan {0} changed, with the router's own undo "
        "timer of {1} s.".format(plan.restore_of, plan.window)
    ]


def _reboot_line(plan: ScriptPlan) -> list[str]:
    return [
        "# If the router reboots or its web service restarts in those "
        "{0} s, the change stays.".format(plan.window)
    ]


def _touches_line(plan: ScriptPlan) -> list[str]:
    return ["# Touches: " + ", ".join(touches_of(plan.ops))]


def _undo_line(plan: ScriptPlan) -> list[str]:
    if plan.kind == KIND_APPLY:
        return [
            "# To undo it later, on the Newton computer: newton-router-setup "
            "{0} owner-run {1}".format(plan.device, plan.restore_sid)
        ]
    return []


def _plan_var(plan: ScriptPlan) -> list[str]:
    return ["PLAN='{0}'".format(plan.sid)]


def _window_var(plan: ScriptPlan) -> list[str]:
    return ["WINDOW={0}".format(plan.window)]


def _preconditions(plan: ScriptPlan) -> list[str]:
    lines: list[str] = []
    for key, value in plan.preconditions:
        if value is None:
            lines.append("absent '{0}'".format(key))
        else:
            lines.append("want '{0}' '{1}'".format(key, value))
    return lines


def _stages(plan: ScriptPlan) -> list[str]:
    lines: list[str] = []
    for verb, key, value in plan.ops:
        if value is None:
            lines.append("stage uci -P \"$D\" {0} '{1}'".format(verb, key))
        else:
            lines.append(
                "stage uci -P \"$D\" {0} '{1}={2}'".format(verb, key, value)
            )
    return lines


_EXPANDERS: dict[str, Callable[[ScriptPlan], list[str]]] = {
    "kind_line": _kind_line,
    "plan_line": _plan_line,
    "purpose_line": _purpose_line,
    "reboot_line": _reboot_line,
    "touches_line": _touches_line,
    "undo_line": _undo_line,
    "plan_var": _plan_var,
    "window_var": _window_var,
    "preconditions": _preconditions,
    "stages": _stages,
}


_MARKER_RE = re.compile(r"^@@([a-z_]+)@@$")


def render_script(plan: ScriptPlan) -> bytes:
    """The bytes of the script for one plan.

    The bytes are deterministic: the same plan always renders the same
    bytes, and nothing that is not in the plan is in them.
    """
    _check_plan(plan)
    lines: list[str] = []
    for part in TEMPLATE_LINES:
        marker = _MARKER_RE.fullmatch(part)
        expander = _EXPANDERS.get(marker.group(1)) if marker else None
        if expander is None:
            lines.append(part)
        else:
            lines.extend(expander(plan))
    return ("\n".join(lines) + "\n").encode("utf-8")


# ---- the parsing -----------------------------------------------------------

_KIND_LINE_RE = re.compile(
    r"^# Newton owner script\. Template owner-v1\. Kind (apply|restore)\.$"
)
_PLAN_LINE_RE = re.compile(
    r"^# Plan ([0-9a-f]{32}) for device ([A-Za-z0-9._-]{1,64})\.$"
)
_APPLY_PURPOSE_RE = re.compile(
    r"^# It changes /etc/config only through one `uci apply`, with the router's "
    r"own undo timer of ([0-9]{1,4}) s\.$"
)
_RESTORE_PURPOSE_RE = re.compile(
    r"^# It restores what plan ([0-9a-f]{32}) changed, with the router's own "
    r"undo timer of ([0-9]{1,4}) s\.$"
)
_REBOOT_RE = re.compile(
    r"^# If the router reboots or its web service restarts in those ([0-9]{1,4}) s, "
    r"the change stays\.$"
)
_TOUCHES_RE = re.compile(r"^# Touches: (.+)$")
_UNDO_RE = re.compile(
    r"^# To undo it later, on the Newton computer: newton-router-setup "
    r"([A-Za-z0-9._-]{1,64}) owner-run ([0-9a-f]{32})$"
)
_PLAN_VAR_RE = re.compile(r"^PLAN='([0-9a-f]{32})'$")
_WINDOW_VAR_RE = re.compile(r"^WINDOW=([0-9]{1,4})$")
_WANT_RE = re.compile(r"^want '([^']*)' '([^']*)'$")
_ABSENT_RE = re.compile(r"^absent '([^']*)'$")
_STAGE_RE = re.compile(r"^stage uci -P \"\$D\" ([a-z_]+) '([^']*)'$")


class _Cursor:
    """The lines of a script, read one at a time."""

    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.index = 0

    def take(self) -> str:
        if self.index >= len(self.lines):
            raise ScriptError("the script ends before the template does")
        line = self.lines[self.index]
        self.index += 1
        return line

    def peek(self) -> str | None:
        if self.index >= len(self.lines):
            return None
        return self.lines[self.index]

    def expect(self, literal: str) -> None:
        line = self.take()
        if line != literal:
            raise ScriptError(
                "line {0} of the script is not the line of the template".format(
                    self.index
                )
            )


def _parse_stage_argument(argument: str) -> tuple[str, str | None]:
    """The key and the value of one stage argument."""
    key, separator, value = argument.partition("=")
    if not separator:
        return key, None
    return key, value


def parse_script(data: bytes) -> ScriptPlan:
    """The plan a rendered script says, or a refusal.

    Every line of the script must be a line of the template or one of
    the exact variable formats; anything else is refused.  The round
    trip ``parse_script(render_script(p)) == p`` holds.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ScriptError("the script must be bytes")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        raise ScriptError("the script is not valid UTF-8") from None
    if "\r" in text:
        raise ScriptError("the script has a carriage return")
    if not text.endswith("\n"):
        raise ScriptError("the script does not end with a newline")
    lines = text[:-1].split("\n")
    cursor = _Cursor(lines)

    cursor.expect("#!/bin/sh")
    kind_match = _KIND_LINE_RE.fullmatch(cursor.take())
    if kind_match is None:
        raise ScriptError("the script does not say which kind it is")
    kind = kind_match.group(1)

    plan_match = _PLAN_LINE_RE.fullmatch(cursor.take())
    if plan_match is None:
        raise ScriptError("the script does not name its plan and device")
    sid = plan_match.group(1)
    device = plan_match.group(2)

    cursor.expect(
        "# Runs as root on your router, sent by newton-router-setup over your "
        "own admin login."
    )

    purpose = cursor.take()
    if kind == KIND_APPLY:
        purpose_match = _APPLY_PURPOSE_RE.fullmatch(purpose)
        if purpose_match is None:
            raise ScriptError("the script does not say what it changes")
        restore_of = ""
        window = int(purpose_match.group(1))
    else:
        purpose_match = _RESTORE_PURPOSE_RE.fullmatch(purpose)
        if purpose_match is None:
            raise ScriptError("the script does not say what it restores")
        restore_of = purpose_match.group(1)
        window = int(purpose_match.group(2))

    reboot_match = _REBOOT_RE.fullmatch(cursor.take())
    if reboot_match is None:
        raise ScriptError("the script does not say what the undo timer does")
    if int(reboot_match.group(1)) != window:
        raise ScriptError("the script names two different windows")

    touches_match = _TOUCHES_RE.fullmatch(cursor.take())
    if touches_match is None:
        raise ScriptError("the script does not say what it touches")

    restore_sid = ""
    if kind == KIND_APPLY:
        undo_match = _UNDO_RE.fullmatch(cursor.take())
        if undo_match is None:
            raise ScriptError("the script does not say how to undo it")
        if undo_match.group(1) != device:
            raise ScriptError("the script names two different devices")
        restore_sid = undo_match.group(2)

    cursor.expect("set -u")
    cursor.expect("PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH")
    cursor.expect("LC_ALL=C; export LC_ALL")
    cursor.expect("umask 077")

    plan_var = _PLAN_VAR_RE.fullmatch(cursor.take())
    if plan_var is None:
        raise ScriptError("the script does not name its plan")
    if plan_var.group(1) != sid:
        raise ScriptError("the script names two different plans")

    window_var = _WINDOW_VAR_RE.fullmatch(cursor.take())
    if window_var is None:
        raise ScriptError("the script does not name its window")
    if int(window_var.group(1)) != window:
        raise ScriptError("the script names two different windows")

    cursor.expect('die() { echo "NEWTON-STOP: $*"; exit 1; }')
    cursor.expect('[ "$(id -u </dev/null)" = 0 ] || die "this must run as root"')
    cursor.expect('echo "NEWTON-APPLYING plan=$PLAN"')
    cursor.expect(
        'W=$(mktemp -d /tmp/newton-owner.XXXXXX </dev/null) || die "no private '
        'directory"'
    )
    cursor.expect("trap 'rm -rf \"$W\"' EXIT")
    cursor.expect("trap 'rm -rf \"$W\"; exit 1' HUP INT TERM")
    cursor.expect(
        '[ -z "$(uci changes </dev/null)" ] || die "the router has uncommitted '
        'changes"'
    )
    for _undo_line in UNDO_LINES:
        cursor.expect(_undo_line)
    cursor.expect(
        'if [ -d /var/run/rpcd/snapshot-files ]; then echo "NEWTON-NOTE: the '
        'router has an empty leftover from a refused change '
        '(/var/run/rpcd/snapshot-files); it does not block Newton"; fi'
    )
    cursor.expect(
        'want() { got=$(uci -q get "$1" </dev/null) && [ "$got" = "$2" ] || die '
        '"the router changed since the plan: $1"; }'
    )
    cursor.expect(
        'absent() { if uci -q get "$1" >/dev/null </dev/null; then die "the '
        'router changed since the plan: $1"; fi; }'
    )

    preconditions: list[tuple[str, str | None]] = []
    while True:
        nxt = cursor.peek()
        if nxt is None:
            break
        want = _WANT_RE.fullmatch(nxt)
        absent = _ABSENT_RE.fullmatch(nxt)
        if want is not None:
            preconditions.append((want.group(1), want.group(2)))
        elif absent is not None:
            preconditions.append((absent.group(1), None))
        else:
            break
        cursor.take()

    cursor.expect('echo "NEWTON-CHECKED plan=$PLAN"')
    cursor.expect(
        'SID=$(ubus call session create "{\\"timeout\\":$((WINDOW + 120))}" '
        "</dev/null | jsonfilter -e '@.ubus_rpc_session')"
    )
    cursor.expect(
        "printf '%s' \"$SID\" | grep -Eq '^[0-9a-f]{32}$' || die \"could not "
        'open a session"'
    )
    cursor.expect(
        'ubus call session grant "{\\"ubus_rpc_session\\":\\"$SID\\",\\"scope\\":'
        '\\"uci\\",\\"objects\\":[[\\"*\\",\\"read\\"],[\\"*\\",\\"write\\"]]}" '
        "</dev/null >/dev/null || die \"could not open a session\""
    )
    cursor.expect(
        'ubus call session grant "{\\"ubus_rpc_session\\":\\"$SID\\",\\"scope\\":'
        '\\"ubus\\",\\"objects\\":[[\\"uci\\",\\"confirm\\"]]}" '
        "</dev/null >/dev/null || die \"could not open a session\""
    )
    cursor.expect('D="/var/run/rpcd/uci-$SID"')
    cursor.expect('mkdir -p "$D" || die "no staging directory"')
    cursor.expect(
        'stage() { "$@" </dev/null >/dev/null 2>"$W/err" && [ ! -s "$W/err" ] '
        '|| die "the router refused a change; nothing was applied"; }'
    )

    ops: list[tuple[str, str, str | None]] = []
    while True:
        nxt = cursor.peek()
        if nxt is None:
            break
        stage = _STAGE_RE.fullmatch(nxt)
        if stage is None:
            break
        verb = stage.group(1)
        if verb not in STAGE_VERBS:
            raise ScriptError(
                "{0} is not a verb an owner script may carry".format(verb)
            )
        key, value = _parse_stage_argument(stage.group(2))
        ops.append((verb, key, value))
        cursor.take()
    if not ops:
        raise ScriptError("the script stages nothing")

    cursor.expect(
        '[ -n "$(uci -P "$D" changes </dev/null)" ] || die "nothing to apply"'
    )
    cursor.expect('echo "NEWTON-STAGED plan=$PLAN"')
    cursor.expect("trap '' HUP INT TERM")
    cursor.expect(
        'ubus call uci apply "{\\"ubus_rpc_session\\":\\"$SID\\",\\"rollback\\":'
        'true,\\"timeout\\":$WINDOW}" </dev/null >/dev/null || die "the router '
        'refused the apply; nothing changed"'
    )
    cursor.expect(
        'echo "NEWTON-APPLIED plan=$PLAN window=$WINDOW session=$SID"'
    )

    if cursor.index != len(lines):
        raise ScriptError("the script has lines the template does not have")

    plan = ScriptPlan(
        sid=sid,
        kind=kind,
        device=device,
        window=window,
        restore_sid=restore_sid,
        restore_of=restore_of,
        preconditions=tuple(preconditions),
        ops=tuple(ops),
    )
    _check_plan(plan)
    expected_touches = ", ".join(touches_of(plan.ops))
    if touches_match.group(1) != expected_touches:
        raise ScriptError("the script does not touch what it says it touches")
    return plan
