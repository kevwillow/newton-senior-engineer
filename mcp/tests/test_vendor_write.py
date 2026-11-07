"""Vendor lint, tokenizer and VyOS script builders (pure module).

The module under test is ``newton_mcp.adapters.vendor_write``: pure functions
and frozen dataclasses, no subprocess and no file or network I/O.  These tests
pin the lint rules the agent's change text must pass, the round trip between
the tokenizer and the renderer, the exact shape of every VyOS script the
builder emits, and the parsers that read the markers back out of device
output.

A statement is DATA: it reaches a script only as tokens the tokenizer
validated, re-rendered by ``render_line``.  No raw agent text is ever
concatenated into a script, so an injection attempt dies in the lint.


"""

from __future__ import annotations

import inspect
import os
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.adapters import vendor_write as vw


ACCEPTED_LINES = (
    "set system host-name p11-test",
    "set interfaces ethernet eth1 description 'lab uplink'",
    "delete service ntp server 1.2.3.4",
)

FORBIDDEN_VALUE_CHARS = (
    ";",
    "|",
    "&",
    "$",
    "`",
    "\\",
    "<",
    ">",
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    "!",
    "*",
    "?",
    '"',
)

CONTROL_CHARS = ("\t", "\r", "\x00", "\x1b", "\x7f")

RESERVED_VERBS = (
    "commit",
    "save",
    "load",
    "run",
    "exit",
    "discard",
    "reboot",
    "rollback",
    "configure",
    "show",
    "compare",
    "confirm",
    "commit-confirm",
    "sudo",
)

ACCESS_WIDENING_SERVICES = (
    ("service", "telnet"),
    ("service", "http"),
    ("service", "https"),
    ("service", "ssh"),
    ("service", "snmp"),
    ("service", "tftp-server"),
    ("service", "ftp"),
)

STAGE_STATEMENTS = [
    ["set", "system", "host-name", "p11-test"],
    ["set", "interfaces", "ethernet", "eth1", "description", "lab uplink"],
    ["delete", "service", "ntp", "server", "1.2.3.4"],
]

# The line that checks the error file exists before any statement runs.
# A ``mktemp`` that fails leaves NEWTON_ERR empty, and then every
# statement would write its stderr into a file that is not there.
MKTEMP_GUARD = (
    'if [ -z "$NEWTON_ERR" ] || [ ! -w "$NEWTON_ERR" ]; then '
    'echo "NEWTON-LINE-ERROR 0"; builtin exit 1; fi'
)


def _all_scripts() -> tuple[vw.SessionSpec, ...]:
    """Every script the builder emits, with one real statement each."""
    return (
        vw.stage_script(STAGE_STATEMENTS),
        vw.apply_script(STAGE_STATEMENTS, 3),
        vw.confirm_script(),
        vw.abort_script(),
        vw.saved_check_script(),
    )


def _assert_no_prompt(script: str) -> None:
    """The commit-confirm invocation must be the exact ``commit-confirm 3 no-prompt`` line.

    VyOS blocks forever on a commit-confirm without it, so this assertion is
    the whole point of the apply script.  The match is on the whole line, so
    a mutated line such as ``commit-confirm 3 no-prompt extra`` fails it.
    The mutation tests call it on a mutated script to prove it really bites.
    """
    lines = script.splitlines()
    assert "commit-confirm 3 no-prompt" in lines, (
        "the commit-confirm must be the exact line 'commit-confirm 3 no-prompt'"
    )
    assert lines.index("compare") < lines.index("commit-confirm 3 no-prompt"), (
        "the commit-confirm must come after the compare"
    )


def _assert_saved_between_markers(script: str) -> None:
    """The ``compare saved`` must sit strictly between the two saved markers.

    The check is by index, so a script that runs the compare outside the
    markers fails it.  A mutation test calls it on a mutated script to prove it bites.
    """
    lines = script.splitlines()
    assert 'echo "NEWTON-BEGIN-SAVED"' in lines, "the saved check needs a begin marker"
    assert 'echo "NEWTON-END-SAVED"' in lines, "the saved check needs an end marker"
    assert "compare saved" in lines, "the saved check must run compare saved"
    begin = lines.index('echo "NEWTON-BEGIN-SAVED"')
    end = lines.index('echo "NEWTON-END-SAVED"')
    compare = lines.index("compare saved")
    assert begin < compare < end, (
        "compare saved must run strictly between the saved markers"
    )


def _longest_run_of(text: str, char: str) -> int:
    """Return the length of the longest run of ``char`` inside ``text``."""
    longest = 0
    current = 0
    for one in text:
        if one == char:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


# ---- tokenizer: what the agent may say ---------------------------------------


def test_tokenizer_accepts_the_documented_statements() -> None:
    """Plain, valued and delete statements all parse into tokens."""
    parsed = vw.parse_lines("vyos", "\n".join(ACCEPTED_LINES))
    assert parsed == [
        ["set", "system", "host-name", "p11-test"],
        ["set", "interfaces", "ethernet", "eth1", "description", "lab uplink"],
        ["delete", "service", "ntp", "server", "1.2.3.4"],
    ]


def test_tokenizer_skips_blank_and_comment_lines() -> None:
    """Blank lines and ``#`` comments are not statements."""
    text = "\n".join(
        [
            "",
            "   ",
            "# a comment",
            "  # an indented comment",
            "set system host-name p11-test",
        ]
    )
    assert vw.parse_lines("vyos", text) == [
        ["set", "system", "host-name", "p11-test"]
    ]


@pytest.mark.parametrize("char", FORBIDDEN_VALUE_CHARS)
def test_tokenizer_refuses_every_forbidden_char_in_a_value(
    char: str,
) -> None:
    """Shell and CLI metacharacters never reach a statement."""
    line = f"set system host-name value{char}tail"
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", line)


@pytest.mark.parametrize("char", CONTROL_CHARS)
def test_tokenizer_refuses_control_chars(char: str) -> None:
    """Tab, CR, NUL, ESC and DEL are refused."""
    line = f"set system host-name value{char}tail"
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", line)


def test_tokenizer_refuses_non_ascii() -> None:
    """A non-ASCII character is refused."""
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", "set system host-name p11-tést")


@pytest.mark.parametrize("verb", RESERVED_VERBS)
def test_tokenizer_refuses_reserved_verbs(verb: str) -> None:
    """Only set|delete|comment are allowed, and the verb is named."""
    with pytest.raises(vw.LintError) as excinfo:
        vw.parse_lines("vyos", f"{verb} system host-name p11-test")
    assert verb in str(excinfo.value)


def test_tokenizer_refuses_uppercase_verb() -> None:
    """Verbs are lower case only."""
    with pytest.raises(vw.LintError) as excinfo:
        vw.parse_lines("vyos", "SET system host-name p11-test")
    assert "SET" in str(excinfo.value)


@pytest.mark.parametrize(
    "line",
    (
        "set system login user x",
        "delete system login user x",
        "set system config-management commit-confirm action reload",
        "delete system config-management commit-confirm",
    ),
)
def test_tokenizer_refuses_refused_path_prefixes(line: str) -> None:
    """Login and config-management paths are refused outright."""
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", line)


@pytest.mark.parametrize("service", ACCESS_WIDENING_SERVICES)
def test_tokenizer_refuses_access_widening_services(
    service: tuple[str, str],
) -> None:
    """Services that widen access are refused by default."""
    line = " ".join(("set", *service, "port", "2222"))
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", line)


def test_tokenizer_refuses_double_quotes() -> None:
    """Double quotes are refused; single quotes are the quoting."""
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", 'set system host-name "p11-test"')


def test_tokenizer_refuses_unterminated_quote() -> None:
    """An unterminated quoted value is refused."""
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", "set system host-name 'p11-test")


def test_tokenizer_refuses_a_401_char_line() -> None:
    """A line longer than 400 chars is refused."""
    prefix = "set system host-name "
    line = prefix + "a" * (401 - len(prefix))
    assert len(line) == 401
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", line)


def test_tokenizer_refuses_201_statements() -> None:
    """201 statements are refused, 200 are allowed."""
    body = "\n".join(f"set system host-name host{index}" for index in range(200))
    assert len(vw.parse_lines("vyos", body)) == 200
    too_many = body + "\nset system host-name host200"
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", too_many)


def test_tokenizer_refuses_a_statement_with_only_a_verb() -> None:
    """A statement needs a verb and at least one path word."""
    for line in ("set", "delete", "comment"):
        with pytest.raises(vw.LintError):
            vw.parse_lines("vyos", line)


def test_tokenizer_refuses_comment_without_quoted_text() -> None:
    """A comment statement needs a quoted last token."""
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", "comment system host-name")
    parsed = vw.parse_lines("vyos", "comment system host-name 'lab note'")
    assert parsed == [["comment", "system", "host-name", "lab note"]]


def test_tokenizer_allows_newton_named_tokens() -> None:
    """VyOS has no reserved-name rule for newton- names."""
    parsed = vw.parse_lines("vyos", "set system host-name newton-lab")
    assert parsed == [["set", "system", "host-name", "newton-lab"]]


def test_tokenizer_refuses_other_platforms() -> None:
    """Routeros and junos have their own rules; the rest is refused."""
    for platform in ("openwrt", ""):
        with pytest.raises(ValueError):
            vw.parse_lines(platform, "set system host-name p11-test")
    # routeros is a platform of its own now, and a VyOS line is not a
    # RouterOS statement: it has to start with a menu path.
    with pytest.raises(vw.LintError):
        vw.parse_lines("routeros", "set system host-name p11-test")
    with pytest.raises(vw.LintError):
        vw.render_line("routeros", ["set", "system", "host-name", "p11-test"])
    # junos is a platform of its own, and a VyOS line is not
    # a Junos statement: it has to start with a verb of the four and to
    # name a hierarchy of the allow list.
    with pytest.raises(vw.LintError):
        vw.parse_lines("junos", "set system login user newton")
    with pytest.raises(vw.LintError):
        vw.render_line("junos", ["set", "system", "login", "user", "newton"])


# ---- tokenizer and renderer round trip --------------------------------------


@pytest.mark.parametrize("line", ACCEPTED_LINES)
def test_render_and_parse_round_trip(line: str) -> None:
    """What the owner sees is what the device is sent."""
    statements = vw.parse_lines("vyos", line)
    rendered = vw.render_line("vyos", statements[0])
    assert rendered == line
    assert vw.parse_lines("vyos", rendered) == statements


def test_render_reemits_a_quoted_value_quoted() -> None:
    """A value with a space comes back in single quotes."""
    statements = vw.parse_lines("vyos", "set interfaces ethernet eth1 description 'lab uplink'")
    assert vw.render_line("vyos", statements[0]) == (
        "set interfaces ethernet eth1 description 'lab uplink'"
    )


def test_render_refuses_tokens_the_vendor_refuses() -> None:
    """The renderer is the second gate, not a bypass."""
    with pytest.raises(vw.LintError):
        vw.render_line("vyos", ["set", "system", "host-name", "x; reboot"])
    with pytest.raises(vw.LintError):
        vw.render_line("vyos", ["set", "system", "host-name", ""])


def test_lint_message_never_echoes_more_than_80_chars() -> None:
    """A lint message is a short reason, never the whole line."""
    prefix = "set system host-name "
    long_line = prefix + "a" * 400
    refusals = (
        long_line,
        "set system host-name p11-test; reboot",
        "set system login user x",
        "set service ssh port 2222",
        "set system host-name 'unterminated",
        'set system host-name "double"',
        "SET system host-name p11-test",
        "commit",
        "set",
        "comment system host-name",
    )
    for line in refusals:
        with pytest.raises(vw.LintError) as excinfo:
            vw.parse_lines("vyos", line)
        message = str(excinfo.value)
        assert len(message) <= 80, (line[:40], message)
        assert "a" * 80 not in message, line[:40]


# ---- builders ---------------------------------------------------------------


def test_every_builder_returns_the_exact_remote() -> None:
    """The remote command string is pinned per builder."""
    assert vw.stage_script(STAGE_STATEMENTS).remote == "vbash -s"
    assert vw.apply_script(STAGE_STATEMENTS, 3).remote == "vbash -s"
    assert vw.confirm_script().remote == "vbash -s"
    assert vw.abort_script().remote == "vbash -s"
    assert vw.saved_check_script().remote == "vbash -s"
    assert vw.status_command().remote == "systemctl is-active commit-confirm.timer"
    assert vw.status_command().stdin == ""
    assert vw.read_config_command().remote == (
        "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands"
    )
    assert vw.read_config_command().stdin == ""
    assert vw.ping_command("10.0.0.1").remote == "ping -c 2 -W 2 -- 10.0.0.1"
    assert vw.ping_command("10.0.0.1").stdin == ""


def test_every_script_starts_with_the_template_and_ends_with_exit() -> None:
    """The shell template is sourced first, exit is last."""
    for spec in _all_scripts():
        lines = spec.stdin.splitlines()
        assert lines[0] == "source /opt/vyatta/etc/functions/script-template"
        assert lines[-1] == "exit"


def test_apply_script_carries_commit_confirm_with_no_prompt() -> None:
    """The commit-confirm carries the minutes and the no-prompt word."""
    script = vw.apply_script(STAGE_STATEMENTS, vw.minutes_for(150)).stdin
    assert "commit-confirm 3 no-prompt" in script
    _assert_no_prompt(script)


def test_stage_script_prints_the_diff_between_markers() -> None:
    """The candidate run shows the diff, then discards."""
    script = vw.stage_script(STAGE_STATEMENTS).stdin
    lines = script.splitlines()
    assert 'echo "NEWTON-BEGIN-DIFF"' in lines
    assert 'echo "NEWTON-END-DIFF"' in lines
    assert "compare" in lines
    assert "discard" in lines
    assert lines.index('echo "NEWTON-BEGIN-DIFF"') < lines.index("compare")
    assert lines.index("compare") < lines.index('echo "NEWTON-END-DIFF"')
    assert lines.index('echo "NEWTON-END-DIFF"') < lines.index("discard")


def test_every_statement_is_guarded_by_its_own_line_number() -> None:
    """A failing statement names itself and discards the candidate.

    The guard is the stderr file: VyOS reports a refused path on stderr
    and still exits zero, so the exit status says nothing.  a sibling test pins
    the guard this test looks for.
    """
    scripts = (
        vw.stage_script(STAGE_STATEMENTS).stdin,
        vw.apply_script(STAGE_STATEMENTS, 3).stdin,
    )
    for script in scripts:
        assert 'echo "NEWTON-LINE-ERROR 1"' in script
        assert 'echo "NEWTON-LINE-ERROR 3"' in script
        assert 'echo "NEWTON-LINE-ERROR 4"' not in script
        assert script.count('rm -f "$NEWTON_ERR"; builtin exit 1;') == 3


def test_abort_reverts_before_it_stops_the_timer() -> None:
    """The timer is stopped only after a successful revert."""
    script = vw.abort_script().stdin
    lines = script.splitlines()
    assert script.index("revert_soft") < script.index("systemctl stop commit-confirm.timer")
    rc_index = next(i for i, line in enumerate(lines) if line.startswith("NEWTON_ABORT_RC=$?"))
    guard_index = next(i for i, line in enumerate(lines) if "-eq 0" in line)
    stop_index = next(
        i for i, line in enumerate(lines) if "systemctl stop commit-confirm.timer" in line
    )
    fi_index = next(i for i, line in enumerate(lines) if line.strip() == "fi")
    assert rc_index < guard_index < stop_index < fi_index
    assert lines[guard_index].lstrip().startswith("if ")
    assert 'echo "NEWTON-ABORT revert_rc=' in script


def test_no_statement_text_lands_outside_a_verb_line() -> None:
    """Agent text only ever appears on a set|delete|comment line."""
    for spec in (vw.stage_script(STAGE_STATEMENTS), vw.apply_script(STAGE_STATEMENTS, 3)):
        lines = spec.stdin.splitlines()
        for tokens in STAGE_STATEMENTS:
            rendered = vw.render_line("vyos", tokens)
            hits = [i for i, line in enumerate(lines) if rendered in line]
            assert len(hits) == 1, rendered
            assert lines[hits[0]].startswith(("set ", "delete ", "comment ")), rendered


def test_quoted_value_reaches_the_script_quoted() -> None:
    """The quoted value is re-emitted quoted inside the script."""
    statements = vw.parse_lines(
        "vyos", "set interfaces ethernet eth1 description 'lab uplink'"
    )
    script = vw.apply_script(statements, 3).stdin
    assert "set interfaces ethernet eth1 description 'lab uplink'" in script


def test_injection_never_reaches_a_script() -> None:
    """An injection attempt dies in the lint, in both gates."""
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", "set system host-name x; reboot")
    with pytest.raises(vw.LintError):
        vw.stage_script([["set", "system", "host-name", "x; reboot"]])
    with pytest.raises(vw.LintError):
        vw.apply_script([["set", "system", "host-name", "x; reboot"]], 3)


def test_builders_refuse_a_reserved_verb() -> None:
    """The builder re-checks the verb, it does not trust its caller."""
    with pytest.raises(vw.LintError):
        vw.stage_script([["commit"]])
    with pytest.raises(vw.LintError):
        vw.apply_script([["commit"]], 3)


def test_ping_command_refuses_a_host_outside_the_charset() -> None:
    """The ping target is bounded before it reaches a remote string."""
    for host in ("-oProxyCommand=id", "host name", "", "a" * 254, "host; reboot"):
        with pytest.raises(vw.LintError):
            vw.ping_command(host)


def test_saved_check_script_uses_compare_saved_between_markers() -> None:
    """The saved check runs in config mode around compare saved."""
    script = vw.saved_check_script().stdin
    lines = script.splitlines()
    assert "configure" in lines
    assert "compare saved" in lines
    assert 'echo "NEWTON-BEGIN-SAVED"' in lines
    assert 'echo "NEWTON-END-SAVED"' in lines
    _assert_saved_between_markers(script)


def test_confirm_script_confirms_and_reports_the_rc() -> None:
    """The confirm script confirms and prints its own rc."""
    script = vw.confirm_script().stdin
    lines = script.splitlines()
    assert "confirm" in lines
    assert 'echo "NEWTON-CONFIRMED rc=$?"' in lines


def test_apply_script_commits_after_the_compare() -> None:
    """The apply script compares, commits, then reports the rc."""
    script = vw.apply_script(STAGE_STATEMENTS, 3).stdin
    lines = script.splitlines()
    assert lines.index("compare") < lines.index("commit-confirm 3 no-prompt")
    assert lines.index("commit-confirm 3 no-prompt") < lines.index(
        'echo "NEWTON-COMMITTED rc=$?"'
    )


# ---- minutes ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("timeout_s", "expected"),
    ((60, 1), (61, 2), (120, 2), (600, 10), (601, 10), (1, 1), (59, 1)),
)
def test_minutes_for_maps_seconds_to_minutes(
    timeout_s: int, expected: int
) -> None:
    """Seconds become minutes, rounded up and clamped to 1..10."""
    assert vw.minutes_for(timeout_s) == expected


@pytest.mark.parametrize("timeout_s", (0, -1, -600))
def test_minutes_for_refuses_a_non_positive_timeout(timeout_s: int) -> None:
    """A timeout of zero or less is refused."""
    with pytest.raises(ValueError):
        vw.minutes_for(timeout_s)


def test_minutes_for_refuses_a_bool() -> None:
    """A bool is not a timeout."""
    for value in (True, False):
        with pytest.raises(TypeError):
            vw.minutes_for(value)


# ---- parsers ----------------------------------------------------------------


def test_parse_stage_returns_the_diff_between_the_markers() -> None:
    """Only the text between the markers is the diff."""
    out = "\n".join(
        [
            "NEWTON-BEGIN-DIFF",
            "[edit system host-name]",
            '+host-name "p11-test"',
            "NEWTON-END-DIFF",
            "discard",
        ]
    )
    result = vw.parse_stage(out)
    assert result.ok is True
    assert result.bad_line is None
    assert result.diff == '[edit system host-name]\n+host-name "p11-test"'


def test_parse_stage_reports_the_bad_line() -> None:
    """A line error names the statement that failed."""
    out = "NEWTON-LINE-ERROR 2\n"
    result = vw.parse_stage(out)
    assert result.ok is False
    assert result.bad_line == 2
    assert result.diff == ""


def test_parse_stage_ignores_a_marker_inside_a_description() -> None:
    """Only an exact marker line counts, and the last one wins."""
    out = "\n".join(
        [
            "set system description 'NEWTON-BEGIN-DIFF'",
            "NEWTON-BEGIN-DIFF",
            "noise",
            "NEWTON-BEGIN-DIFF",
            "the real diff",
            "NEWTON-END-DIFF",
        ]
    )
    result = vw.parse_stage(out)
    assert result.ok is True
    assert result.diff == "the real diff"


def test_parse_stage_without_markers_is_not_ok() -> None:
    """No markers means no diff and no ok."""
    result = vw.parse_stage("compare said nothing useful\n")
    assert result.ok is False
    assert result.diff == ""
    assert result.bad_line is None


def test_parse_apply_reads_the_committed_marker() -> None:
    """Exactly one committed marker with rc 0 means committed."""
    assert vw.parse_apply("NEWTON-COMMITTED rc=0\n") == "committed"


def test_parse_apply_is_failed_without_the_marker() -> None:
    """A missing marker means failed, never committed."""
    assert vw.parse_apply("") == "failed"
    assert vw.parse_apply("NEWTON-COMMITTED rc=1\n") == "failed"
    assert vw.parse_apply("NEWTON-COMMITTED rc=0\nNEWTON-COMMITTED rc=0\n") == "failed"


def test_parse_apply_reports_a_line_error() -> None:
    """A line error is its own outcome."""
    assert vw.parse_apply('NEWTON-LINE-ERROR 3\n') == "line_error"


def test_parse_apply_ignores_a_marker_inside_a_quoted_description() -> None:
    """A description that quotes the marker does not commit anything."""
    out = "set system description 'NEWTON-COMMITTED rc=0'\n"
    assert vw.parse_apply(out) == "failed"
    out = "set system description 'NEWTON-COMMITTED rc=0'\nNEWTON-COMMITTED rc=0\n"
    assert vw.parse_apply(out) == "committed"


def test_parse_saved_reads_the_saved_marker_text() -> None:
    """The saved check is true only for the no-change text."""
    clean = "\n".join(
        [
            "NEWTON-BEGIN-SAVED",
            "No changes between working and saved configurations.",
            "NEWTON-END-SAVED",
        ]
    )
    assert vw.parse_saved(clean) is True
    dirty = "\n".join(
        ["NEWTON-BEGIN-SAVED", "[edit interfaces ethernet eth1]", "NEWTON-END-SAVED"]
    )
    assert vw.parse_saved(dirty) is False
    assert vw.parse_saved("No changes between working and saved configurations.") is False


def test_parse_reload_mode_reads_the_exact_line() -> None:
    """Reload mode is the exact action line, nothing else."""
    reload_line = "set system config-management commit-confirm action 'reload'"
    assert vw.parse_reload_mode(reload_line + "\n") is True
    assert (
        vw.parse_reload_mode(
            "set system config-management commit-confirm action 'reboot'\n"
        )
        is False
    )
    assert vw.parse_reload_mode("# " + reload_line + "\n") is False
    assert vw.parse_reload_mode("") is False


def test_parse_timer_reads_the_timer_state() -> None:
    """Active means a pending revert, inactive means none."""
    assert vw.parse_timer("active\n") == "pending"
    assert vw.parse_timer("inactive\n") == "idle"
    assert vw.parse_timer("failed\n") == "unknown"
    assert vw.parse_timer("") == "unknown"


# ---- purity and the planted-defect meta test --------------------------------


def test_module_is_pure() -> None:
    """The module never runs a command and never touches a file."""
    source = inspect.getsource(vw)
    for needle in (
        "import subprocess",
        "import os",
        "import socket",
        "shell=True",
        "os.system",
        "eval(",
        "exec(",
        "open(",
    ):
        assert needle not in source, needle


def test_meta_the_no_prompt_assertion_catches_a_mutated_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The no-prompt test fails on a script that lost the word.

    The assertion is written as a function so it can be run twice: once on
    the real output, and once on an output whose ``no-prompt`` was patched
    out.  The second run must raise, or the test proves nothing.
    """
    real = vw.apply_script(STAGE_STATEMENTS, vw.minutes_for(150)).stdin
    _assert_no_prompt(real)

    mutated = real.replace("no-prompt", "")
    monkeypatch.setattr(
        vw,
        "apply_script",
        lambda stmts, minutes: vw.SessionSpec(remote="vbash -s", stdin=mutated),
    )
    patched = vw.apply_script(STAGE_STATEMENTS, vw.minutes_for(150)).stdin
    with pytest.raises(AssertionError):
        _assert_no_prompt(patched)


def test_the_raw_text_rule_covers_every_line() -> None:
    """The lint is fail-closed, a comment line cannot carry a metacharacter.

    The raw text of every line is checked, not only the lines that become
    statements.  A comment is dropped, so nothing unsafe reaches the device
    either way, but refusing the text outright keeps one rule for the whole
    change text.
    """
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", "# a comment with a semicolon; inside")
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", "# a comment with a tab\tinside")


def test_an_empty_quoted_value_is_refused() -> None:
    """An empty value is refused, so the round trip cannot break."""
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", "set system host-name ''")
    with pytest.raises(vw.LintError):
        vw.stage_script([[]])
    with pytest.raises(vw.LintError):
        vw.stage_script([["set"]])


# ---- review fixes ------------------------


def test_lint_message_never_echoes_more_than_20_chars_of_agent_text() -> None:
    """A lint message carries a short piece of the agent's text.

    The refused verb, path, character and service messages all echo agent
    text, so each one cuts that text to 20 characters and adds an ellipsis.
    A 300 character verb or a 300 character path word therefore cannot put
    300 characters into an error message.
    """
    long_verb = "v" * 300
    long_word = "p" * 300
    cases = (
        (f"{long_verb} system host-name p11-test", long_verb, "v"),
        (f"set system login {long_word}", long_word, "p"),
        (f"set service ssh {long_word}", long_word, "p"),
    )
    for line, agent_text, char in cases:
        with pytest.raises(vw.LintError) as excinfo:
            vw.parse_lines("vyos", line)
        message = str(excinfo.value)
        assert len(message) <= 120, (line[:40], message)
        assert agent_text not in message, line[:40]
        assert "..." in message, (line[:40], message)
        assert _longest_run_of(message, char) <= 20, (line[:40], message)


def test_tokenizer_refuses_a_token_with_reserved_marker_text() -> None:
    """A token that carries NEWTON- is refused.

    An agent token that holds the marker text could forge a marker in the
    device output, so the tokenizer refuses it and the renderer refuses it
    too.  The check is case-sensitive: a lower case name is still fine.
    """
    for line in (
        "set system description 'NEWTON-COMMITTED rc=0'",
        "set x NEWTON-LINE-ERROR",
        "set x NEWTON-END-DIFF",
    ):
        with pytest.raises(vw.LintError) as excinfo:
            vw.parse_lines("vyos", line)
        assert str(excinfo.value) == "reserved marker text", line
    with pytest.raises(vw.LintError) as excinfo:
        vw.render_line("vyos", ["set", "system", "description", "NEWTON-COMMITTED rc=0"])
    assert str(excinfo.value) == "reserved marker text"
    with pytest.raises(vw.LintError):
        vw.stage_script([["set", "system", "description", "NEWTON-COMMITTED rc=0"]])
    assert vw.parse_lines("vyos", "set system host-name newton-lab") == [
        ["set", "system", "host-name", "newton-lab"]
    ]


def test_a_prefixed_or_embedded_marker_line_does_not_count() -> None:
    """Only a marker line of its own counts.

    A diff line that starts with ``+`` or ``-``, or a marker that sits
    inside a longer line, is device output and not a marker.
    """
    for line in (
        "+NEWTON-COMMITTED rc=0",
        "-NEWTON-COMMITTED rc=0",
        "NEWTON-COMMITTED rc=0 extra",
        "set system description 'NEWTON-COMMITTED rc=0'",
    ):
        assert vw.parse_apply(line + "\n") == "failed", line
    stage = vw.parse_stage("+NEWTON-BEGIN-DIFF\nthe diff\n-NEWTON-END-DIFF\n")
    assert stage.ok is False
    assert stage.diff == ""
    assert stage.bad_line is None
    saved = vw.parse_saved(
        "+NEWTON-BEGIN-SAVED\n"
        "No changes between working and saved configurations.\n"
        "-NEWTON-END-SAVED\n"
    )
    assert saved is False


def test_parse_reload_mode_needs_the_exact_line() -> None:
    """The reload line must match exactly, nothing is stripped."""
    reload_line = "set system config-management commit-confirm action 'reload'"
    assert vw.parse_reload_mode(reload_line + "\n") is True
    assert vw.parse_reload_mode("  " + reload_line + "\n") is False
    assert vw.parse_reload_mode("\t" + reload_line + "\n") is False
    assert vw.parse_reload_mode(reload_line + " \n") is False


def test_the_empty_quoted_value_is_refused_and_documented() -> None:
    """An empty quoted value is refused, and the docstring says so."""
    with pytest.raises(vw.LintError):
        vw.parse_lines("vyos", "set system host-name ''")
    with pytest.raises(vw.LintError):
        vw.render_line("vyos", ["set", "system", "host-name", ""])
    for docstring in (vw.parse_lines.__doc__, vw.render_line.__doc__):
        assert docstring is not None
        assert "''" in docstring


def test_meta_the_exact_commit_confirm_line_catches_a_mutated_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """'commit-confirm 3 no-prompt extra' fails the exact-line check.

    The assertion is written as a function so it can be run twice: once on
    the real output, and once on an output whose commit-confirm line was
    mutated.  The second run must raise, or the test proves nothing.
    """
    real = vw.apply_script(STAGE_STATEMENTS, vw.minutes_for(150)).stdin
    _assert_no_prompt(real)

    mutated = real.replace(
        "commit-confirm 3 no-prompt", "commit-confirm 3 no-prompt extra"
    )
    assert mutated != real
    monkeypatch.setattr(
        vw,
        "apply_script",
        lambda stmts, minutes: vw.SessionSpec(remote="vbash -s", stdin=mutated),
    )
    patched = vw.apply_script(STAGE_STATEMENTS, vw.minutes_for(150)).stdin
    with pytest.raises(AssertionError):
        _assert_no_prompt(patched)


def test_meta_the_saved_check_check_catches_a_mutated_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compare saved outside the markers fails the between-markers check.

    The assertion is written as a function so it can be run twice: once on
    the real output, and once on an output whose compare was moved out of
    the markers.  The second run must raise, or the test proves nothing.
    """
    real = vw.saved_check_script().stdin
    _assert_saved_between_markers(real)

    lines = real.splitlines()
    lines.remove("compare saved")
    lines.insert(2, "compare saved")
    mutated = "\n".join(lines) + "\n"
    monkeypatch.setattr(
        vw,
        "saved_check_script",
        lambda: vw.SessionSpec(remote="vbash -s", stdin=mutated),
    )
    patched = vw.saved_check_script().stdin
    with pytest.raises(AssertionError):
        _assert_saved_between_markers(patched)


# ---- review fixes ------------------------


def test_save_script_saves_in_config_mode_and_reports_the_rc() -> None:
    """The save script saves the running config and prints its rc."""
    spec = vw.save_script()
    assert spec.remote == "vbash -s"
    assert spec.stdin == (
        "source /opt/vyatta/etc/functions/script-template\n"
        "configure\n"
        "save\n"
        'echo "NEWTON-SAVED rc=$?"\n'
        "exit\n"
    )


def _assert_saved_marker_is_exact(out: str) -> None:
    """The saved marker counts only as one exact line with rc zero.

    The same exact-line rules as the other markers apply: a marker inside a
    description, a prefixed marker, a marker with extra text or a marker
    with another rc does not count, and two marker lines are not a save
    either.
    """
    assert vw.parse_saved_ok(out) is True, out
    for other in (
        "NEWTON-SAVED rc=1",
        "NEWTON-SAVED rc=0 extra",
        "+NEWTON-SAVED rc=0",
        "set system description 'NEWTON-SAVED rc=0'",
        "NEWTON-SAVED rc=00",
    ):
        assert vw.parse_saved_ok(other + "\n") is False, other
    assert vw.parse_saved_ok(out + "NEWTON-SAVED rc=0\n") is False, out


def test_the_saved_marker_counts_only_as_one_exact_line() -> None:
    """Exactly one exact marker line with rc zero means saved."""
    _assert_saved_marker_is_exact("NEWTON-SAVED rc=0\n")
    assert vw.parse_saved_ok("") is False
    assert vw.parse_saved_ok("NEWTON-SAVED rc=0\nNEWTON-SAVED rc=0\n") is False


def test_meta_the_saved_marker_check_catches_a_mutated_output() -> None:
    """A second marker line fails the exactly-one rule.

    The assertion is written as a function so it can be run twice: once on
    the real output, and once on an output that carries the marker twice.
    The second run must raise, or the test proves nothing.
    """
    _assert_saved_marker_is_exact("NEWTON-SAVED rc=0\n")
    with pytest.raises(AssertionError):
        _assert_saved_marker_is_exact("NEWTON-SAVED rc=0\nNEWTON-SAVED rc=0\n")


def test_parse_apply_reads_the_four_marker_combinations() -> None:
    """Committed, line error, both and neither are four outcomes.

    Device-originated text must not turn a committed change into "nothing
    was committed": a committed marker together with a line error is a
    failure, not a clean line error.
    """
    assert vw.parse_apply("NEWTON-COMMITTED rc=0\n") == "committed"
    assert vw.parse_apply("NEWTON-LINE-ERROR 3\n") == "line_error"
    assert vw.parse_apply("NEWTON-COMMITTED rc=0\nNEWTON-LINE-ERROR 3\n") == "failed"
    assert vw.parse_apply("NEWTON-LINE-ERROR 3\nNEWTON-COMMITTED rc=0\n") == "failed"
    assert vw.parse_apply("") == "failed"
    assert vw.parse_apply("NEWTON-COMMITTED rc=0\nNEWTON-COMMITTED rc=0\n") == "failed"


def _assert_abort_script_ordering(script: str) -> None:
    """The timer is stopped only inside the successful revert block.

    The stop line must be the only line that mentions ``systemctl stop``,
    it must sit inside the ``NEWTON_ABORT_RC -eq 0`` block and it must come
    after the revert line.
    """
    lines = script.splitlines()
    stop_indexes = [
        index for index, line in enumerate(lines) if "systemctl stop" in line
    ]
    assert len(stop_indexes) == 1, script
    stop_index = stop_indexes[0]
    assert lines[stop_index].strip() == "sudo systemctl stop commit-confirm.timer", script

    guard_indexes = [
        index
        for index, line in enumerate(lines)
        if line.strip() == 'if [ "$NEWTON_ABORT_RC" -eq 0 ]; then'
    ]
    assert len(guard_indexes) == 1, script
    fi_indexes = [index for index, line in enumerate(lines) if line.strip() == "fi"]
    assert len(fi_indexes) == 1, script
    revert_indexes = [
        index for index, line in enumerate(lines) if "revert_soft" in line
    ]
    assert len(revert_indexes) == 1, script

    assert guard_indexes[0] < stop_index < fi_indexes[0], script
    assert revert_indexes[0] < stop_index, script


def test_the_timer_is_stopped_only_inside_the_successful_revert_block() -> None:
    """The stop line is inside the guard and after the revert."""
    _assert_abort_script_ordering(vw.abort_script().stdin)


def test_meta_the_abort_ordering_check_catches_a_mutated_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stop line outside the guard fails the ordering check.

    The assertion is written as a function so it can be run twice: once on
    the real script, and once on a script whose stop line was moved out of
    the guard block.  The second run must raise, or the test proves nothing.
    """
    real = vw.abort_script().stdin
    _assert_abort_script_ordering(real)

    lines = real.splitlines()
    stop = "  sudo systemctl stop commit-confirm.timer"
    lines.remove(stop)
    guard = 'if [ "$NEWTON_ABORT_RC" -eq 0 ]; then'
    lines.insert(lines.index(guard), stop)
    mutated = "\n".join(lines) + "\n"
    monkeypatch.setattr(
        vw,
        "abort_script",
        lambda: vw.SessionSpec(remote="vbash -s", stdin=mutated),
    )
    patched = vw.abort_script().stdin
    with pytest.raises(AssertionError):
        _assert_abort_script_ordering(patched)


# ---- review fixes --------------


def test_has_line_compares_the_tokens_not_the_quotes() -> None:
    """The real matcher compares tokenised statements.

    Stripping every quote made ``set a 'b c'`` and ``set a b 'c'`` the
    same statement.  They are not: the first is the path ``a`` with the
    value ``b c``, the second the path ``a b`` with the value ``c``.
    """
    ops = vw.VyosOps()
    assert ops.has_line("set a 'b c'", "set a 'b c'") is True
    assert ops.has_line("set a b 'c'", "set a 'b c'") is False
    assert ops.has_line("set a b 'c'", "set a b 'c'") is True


def test_has_line_does_not_match_a_longer_line() -> None:
    """'set a b-other' does not satisfy the claim 'set a b'."""
    ops = vw.VyosOps()
    assert ops.has_line("set a b", "set a b") is True
    assert ops.has_line("set a b-other", "set a b") is False
    assert ops.has_line("set a b", "set a b-other") is False


def _assert_no_substring_match(ops: Any, config: str, claim: str) -> None:
    """A longer line that contains the claim does not satisfy the claim."""
    assert ops.has_line(config, claim) is False, claim


def test_meta_the_has_line_check_catches_a_substring_matcher() -> None:
    """A has_line that matches a substring fails the check.

    The assertion is written as a function so it can be run twice: once on
    the real matcher, and once on a matcher that looks for the claim as a
    substring of the configuration.  The second run must raise, or the
    test proves nothing.
    """
    _assert_no_substring_match(vw.VyosOps(), "set a b-other", "set a b")

    class _SubstringOps:
        platform = "vyos"

        def has_line(self, snapshot_text: str, rendered_line: str) -> bool:
            return rendered_line in snapshot_text

    with pytest.raises(AssertionError):
        _assert_no_substring_match(_SubstringOps(), "set a b-other", "set a b")


# ---- a VyOS line error is not in the exit status ---------------------


def _assert_no_pipe_guard(script: str) -> None:
    """The script must not guard a statement with the old ``|| { ... }``.

    VyOS reports a refused path on stderr and exits zero, so the stderr
    file is what catches a VyOS error.  The guard reads that file and the
    exit status of the statement, and the two are joined with ``||``
    inside the ``if``: that is not the old pipe guard, which ran the whole
    guard as the right side of a pipe and never read the file at all.
    """
    assert "|| {" not in script, script
    assert "||{" not in script, script


def _statement_block(lines: list[str]) -> list[str]:
    """The lines of a script that run the statements and their guards."""
    start = lines.index(MKTEMP_GUARD) + 1
    end = start
    while lines[end].startswith(("set ", "delete ", "comment ", 'if [ "$NEWTON_RC" ')):
        end += 1
    return lines[start:end]


def _guard_line(index: int) -> str:
    """The exact guard line of statement ``index``."""
    return (
        f'if [ "$NEWTON_RC" -ne 0 ] || [ -s "$NEWTON_ERR" ]; then '
        f'echo "NEWTON-LINE-ERROR {index}"; '
        f'discard; rm -f "$NEWTON_ERR"; builtin exit 1; fi'
    )


def test_the_statement_writes_its_stderr_to_the_error_file() -> None:
    """Every statement writes its stderr to the error file.

    The exit status of a VyOS statement says nothing: a refused path is
    reported on stderr and the statement still exits zero.  So every
    statement writes its stderr to ``NEWTON_ERR`` and the next line checks
    the file.  Any output at all is a line error.  The exit status of the
    statement is kept as well, so a statement that fails another way
    stops the script too.
    """
    for script in (
        vw.stage_script(STAGE_STATEMENTS).stdin,
        vw.apply_script(STAGE_STATEMENTS, 3).stdin,
    ):
        lines = script.splitlines()
        assert lines[0] == "source /opt/vyatta/etc/functions/script-template"
        assert lines[1] == "configure"
        assert lines[2] == "NEWTON_ERR=$(mktemp)"
        _assert_no_pipe_guard(script)
        block = _statement_block(lines)
        assert len(block) == 2 * len(STAGE_STATEMENTS)
        for index, tokens in enumerate(STAGE_STATEMENTS, start=1):
            rendered = vw.render_line("vyos", tokens)
            assert block[2 * (index - 1)] == (
                f'{rendered} 2>"$NEWTON_ERR"; NEWTON_RC=$?'
            )
            assert block[2 * (index - 1) + 1] == _guard_line(index)


def test_the_error_file_is_removed_on_every_exit_path() -> None:
    """The file is removed before every exit, the last one too."""
    stage = vw.stage_script(STAGE_STATEMENTS).stdin.splitlines()
    applied = vw.apply_script(STAGE_STATEMENTS, 3).stdin.splitlines()
    for script in (stage, applied):
        assert script[-1] == "exit"
        for line in script:
            if line.startswith('if [ "$NEWTON_RC" -ne 0 ]'):
                assert 'rm -f "$NEWTON_ERR"; builtin exit 1;' in line
        clean = [line for line in script if line.strip() == 'rm -f "$NEWTON_ERR"']
        assert len(clean) == 1
    assert stage.index('rm -f "$NEWTON_ERR"') > stage.index("compare")
    assert stage.index('rm -f "$NEWTON_ERR"') < stage.index("discard")
    assert applied.index('rm -f "$NEWTON_ERR"') > applied.index(
        'echo "NEWTON-COMMITTED rc=$?"'
    )


def test_the_staged_and_the_applied_statements_are_the_same_text() -> None:
    """The applied script is the staged script minus the commit."""
    stage = vw.stage_script(STAGE_STATEMENTS).stdin.splitlines()
    applied = vw.apply_script(STAGE_STATEMENTS, 3).stdin.splitlines()
    assert stage[:3] == applied[:3]
    assert _statement_block(stage) == _statement_block(applied)


def test_the_last_statement_check_comes_before_the_commit_confirm() -> None:
    """The line-error path is armed before anything is committed."""
    lines = vw.apply_script(STAGE_STATEMENTS, 3).stdin.splitlines()
    checks = [
        index
        for index, line in enumerate(lines)
        if line.startswith('if [ "$NEWTON_RC" -ne 0 ]')
    ]
    assert len(checks) == len(STAGE_STATEMENTS)
    assert checks[-1] < lines.index("commit-confirm 3 no-prompt")


def test_parse_stage_reports_an_empty_diff() -> None:
    """A diff that says nothing changed is not a candidate."""
    out = "\n".join(
        [
            "NEWTON-BEGIN-DIFF",
            "No changes between working and active configurations",
            "NEWTON-END-DIFF",
        ]
    )
    result = vw.parse_stage(out)
    assert result.no_changes is True
    assert result.ok is False
    assert result.bad_line is None


def test_a_diff_that_quotes_the_text_is_not_an_empty_diff() -> None:
    """Only a line of its own counts as the no-change sentence.

    A description that quotes the sentence is a change, not an empty
    diff, so the sentence is matched line by line.
    """
    out = "\n".join(
        [
            "NEWTON-BEGIN-DIFF",
            "[edit system description]",
            "+description 'No changes between working and active configurations'",
            "NEWTON-END-DIFF",
        ]
    )
    result = vw.parse_stage(out)
    assert result.no_changes is False
    assert result.ok is True


def test_meta_the_no_pipe_guard_check_catches_a_mutated_script() -> None:
    """The old ``||`` guard fails the no-pipe check.

    The assertion is written as a function so it can be run twice: once on
    the real script, and once on a script whose statement is guarded by
    the exit status again.  The second run must raise, or the test proves
    nothing.
    """
    real = vw.stage_script(STAGE_STATEMENTS).stdin
    _assert_no_pipe_guard(real)

    mutated = real.replace(
        '2>"$NEWTON_ERR"',
        '|| { echo "NEWTON-LINE-ERROR 1"; discard; builtin exit 1; }',
    )
    assert mutated != real
    with pytest.raises(AssertionError):
        _assert_no_pipe_guard(mutated)


# ---- a plain ``exit N`` does not end a vbash script ------------------
#
# Measured live on VyOS (vbash -s, configuration mode): a plain ``exit 5``
# is the configuration-mode ``exit`` command.  It prints "Invalid command:
# [5]" and the script carries on, so the guard that stops a script after a
# line error never stopped it and the apply went on to the commit-confirm.
# ``builtin exit 7`` ends the script with rc 7, so the early stop is a
# builtin exit.


BASH_STATEMENTS = [
    ["set", "system", "host-name", "p11-test"],
    ["set", "interfaces", "ethernet", "eth1", "description", "lab uplink"],
]

_EARLY_EXIT_RE = re.compile(r"exit\s+\d")


def _all_generated_scripts() -> tuple[vw.SessionSpec, ...]:
    """Every script the builders emit, save script included."""
    return (
        vw.stage_script(STAGE_STATEMENTS),
        vw.apply_script(STAGE_STATEMENTS, 3),
        vw.confirm_script(),
        vw.abort_script(),
        vw.save_script(),
        vw.saved_check_script(),
    )


def _assert_only_builtin_early_stops(script: str) -> None:
    """Every early stop in a script must be a ``builtin exit N``.

    In the VyOS configuration mode a plain ``exit N`` is the
    configuration-mode command: it prints "Invalid command" and the
    script carries on.  Only ``builtin exit N`` ends the script.  The
    trailing plain ``exit`` that leaves the configuration mode carries no
    number, so it is not an early stop and is not caught here.
    """
    for number, line in enumerate(script.splitlines(), start=1):
        for match in _EARLY_EXIT_RE.finditer(line):
            words = line[: match.start()].split()
            assert words and words[-1] == "builtin", (
                f"line {number}: the early stop {match.group(0)!r} "
                "is not a builtin exit"
            )


def _shell_words(tokens: Sequence[str]) -> str:
    """The words the shell hands to the command, without the quotes."""
    return " ".join(tokens[1:])


def _vyos_shell_preamble(fail_on: str = "", rc_on: str = "",
                         empty_mktemp: bool = False,
                         readonly_mktemp: bool = False) -> str:
    """Shell functions that mimic the VyOS configuration mode.

    ``set`` writes to stderr for the chosen statement, so the guard in
    the script sees a line error.  ``set`` returns 1 for the other chosen
    statement and writes nothing, so the guard has to read the exit
    status as well.  ``exit`` is the configuration-mode command: it prints
    "Invalid command" and lets the script carry on, which is what a plain
    ``exit N`` does inside a vbash script.
    ``commit-confirm`` records that it was called.

    ``empty_mktemp`` makes ``mktemp`` print nothing, so the error file
    cannot be made and the script has to stop before any statement.
    ``readonly_mktemp`` makes ``mktemp`` print the path of a file that
    cannot be written, so the error file exists as a name but the
    statements cannot write their stderr into it.
    """
    lines = [
        f'fail_on="{fail_on}"',
        f'rc_on="{rc_on}"',
        "set() {",
        '  if [ -n "$fail_on" ] && [ "$*" = "$fail_on" ]; then',
        '    echo "Invalid command" >&2',
        "  fi",
        '  if [ -n "$rc_on" ] && [ "$*" = "$rc_on" ]; then',
        "    return 1",
        "  fi",
        "  return 0",
        "}",
        "discard() { return 0; }",
        "compare() { return 0; }",
        'commit-confirm() { echo "NEWTON-COMMIT-CONFIRM-CALLED"; return 0; }',
        "configure() { return 0; }",
        'exit() { echo "Invalid command: $*" >&2; return 0; }',
    ]
    if empty_mktemp:
        lines.append("mktemp() { return 0; }")
    if readonly_mktemp:
        lines.append(
            'mktemp() { echo "/nonexistent-newton-dir/newnton-err"; }'
        )
    return "\n".join(lines) + "\n"


def _run_script_in_bash(
    script: str,
    tmp_path: Path,
    *,
    fail_on: str = "",
    rc_on: str = "",
    empty_mktemp: bool = False,
    readonly_mktemp: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a generated script under bash with the VyOS shell functions.

    The script-template line is replaced by ``true``: the real template
    is on the device, not here.  Everything else is the script the
    builder emitted.  The command is an argv list, never a shell string.
    """
    lines = script.splitlines()
    assert lines[0] == "source /opt/vyatta/etc/functions/script-template"
    lines[0] = "true"
    body = (
        _vyos_shell_preamble(fail_on, rc_on, empty_mktemp, readonly_mktemp)
        + "\n".join(lines)
        + "\n"
    )
    env = dict(os.environ)
    env["TMPDIR"] = str(tmp_path)
    return subprocess.run(
        ["bash"],
        input=body,
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_no_generated_script_has_a_plain_early_stop() -> None:
    """An early stop is always a ``builtin exit N``.

    A plain ``exit N`` in a vbash script is the configuration-mode
    command: it prints "Invalid command" and the script carries on, so
    the guard that stops the script after a line error would not stop it
    and the apply would go on to the commit-confirm.
    """
    for spec in _all_generated_scripts():
        _assert_only_builtin_early_stops(spec.stdin)


def test_the_apply_script_stops_before_the_commit_confirm() -> None:
    """The early stop of every guard is ``builtin exit 1``.

    The guard of the last statement comes before the commit-confirm, so
    the script stops there and nothing is committed.
    """
    lines = vw.apply_script(STAGE_STATEMENTS, 3).stdin.splitlines()
    guards = [
        index
        for index, line in enumerate(lines)
        if line.startswith('if [ "$NEWTON_RC" -ne 0 ]')
    ]
    assert len(guards) == len(STAGE_STATEMENTS)
    for index in guards:
        assert "builtin exit 1" in lines[index], lines[index]
    assert guards[-1] < lines.index("commit-confirm 3 no-prompt")


def test_the_apply_script_stops_at_the_line_error(tmp_path: Path) -> None:
    """A line error in statement 2 stops the script.

    The script runs under bash with the VyOS commands as shell
    functions, so this is the behaviour a vbash script has: the guard
    fires on the stderr file and the script ends there.  The
    commit-confirm must not be reached.
    """
    script = vw.apply_script(BASH_STATEMENTS, 3).stdin
    result = _run_script_in_bash(
        script,
        tmp_path,
        fail_on=_shell_words(BASH_STATEMENTS[1]),
    )

    assert "NEWTON-LINE-ERROR 2" in result.stdout
    assert "NEWTON-COMMIT-CONFIRM-CALLED" not in result.stdout
    assert "NEWTON-COMMITTED rc=0" not in result.stdout
    assert result.returncode == 1


def test_the_apply_script_commits_when_no_statement_errors(
    tmp_path: Path,
) -> None:
    """Without a line error the apply reaches the commit-confirm."""
    script = vw.apply_script(BASH_STATEMENTS, 3).stdin
    result = _run_script_in_bash(script, tmp_path)

    assert "NEWTON-LINE-ERROR" not in result.stdout
    assert "NEWTON-COMMIT-CONFIRM-CALLED" in result.stdout
    assert "NEWTON-COMMITTED rc=0" in result.stdout
    assert result.returncode == 0


def test_meta_the_bash_run_catches_a_plain_exit(tmp_path: Path) -> None:
    """With a plain ``exit 1`` the commit-confirm still runs.

    The emulation is what proves the fix.  The VyOS configuration mode
    ignores a plain ``exit 1``, so the script carries on to the
    commit-confirm: the mutated script is the one the fix removes, and
    it must reach the commit-confirm, or the emulation proves nothing.
    """
    script = vw.apply_script(BASH_STATEMENTS, 3).stdin
    mutated = script.replace("builtin exit 1", "exit 1")
    assert mutated != script

    result = _run_script_in_bash(
        mutated,
        tmp_path,
        fail_on=_shell_words(BASH_STATEMENTS[1]),
    )

    assert "NEWTON-LINE-ERROR 2" in result.stdout
    assert "NEWTON-COMMIT-CONFIRM-CALLED" in result.stdout


# ---- the guard reads the exit status, and the session is prepared --
#
# A review found two holes in
# the guard of a statement:
#
# * the guard read the stderr file only, so a statement that failed with
#   a non-zero exit status and nothing on stderr went on to the
#   commit-confirm.  VyOS reports a refused path on stderr and exits
#   zero, so the stderr file is what catches a VyOS error; the exit
#   status is what catches any other failure.
# * ``mktemp`` can fail, and then ``NEWTON_ERR`` is empty: every
#   statement would write its stderr into a file that is not there, the
#   guard would never fire, and the apply would go on to the
#   commit-confirm.  The script checks the file before the first
#   statement now.
#
# A ``trap ... EXIT`` would be the tidy way to remove the file, but it is
# not usable in the vbash configuration mode, so there is no trap.


def test_the_statement_keeps_its_exit_status() -> None:
    """The statement line records the exit status of the statement.

    The status is captured right after the statement, so the guard can
    read it: ``NEWTON_RC`` is the status of the statement and nothing
    else.
    """
    for script in (
        vw.stage_script(STAGE_STATEMENTS).stdin,
        vw.apply_script(STAGE_STATEMENTS, 3).stdin,
    ):
        lines = script.splitlines()
        block = _statement_block(lines)
        for index, tokens in enumerate(STAGE_STATEMENTS, start=1):
            rendered = vw.render_line("vyos", tokens)
            assert block[2 * (index - 1)] == (
                f'{rendered} 2>"$NEWTON_ERR"; NEWTON_RC=$?'
            )


def test_the_guard_fires_on_a_nonzero_exit_status(tmp_path: Path) -> None:
    """A statement that exits non-zero stops the script.

    VyOS reports a refused path on stderr and exits zero, so the stderr
    file is what catches a VyOS error.  A statement that fails another
    way (a non-zero exit status and an empty stderr file) must stop the
    script too, or the apply would go on to the commit-confirm.
    """
    script = vw.apply_script(BASH_STATEMENTS, 3).stdin
    result = _run_script_in_bash(
        script,
        tmp_path,
        rc_on=_shell_words(BASH_STATEMENTS[1]),
    )

    assert "NEWTON-LINE-ERROR 2" in result.stdout
    assert "NEWTON-COMMIT-CONFIRM-CALLED" not in result.stdout
    assert "NEWTON-COMMITTED rc=0" not in result.stdout
    assert result.returncode == 1


def test_the_early_stop_exits_with_rc_one(tmp_path: Path) -> None:
    """The early stop ends the script with rc 1.

    The rc of the session is what the caller sees, so a stop that exits
    zero would look like a successful session to the caller.
    """
    script = vw.apply_script(BASH_STATEMENTS, 3).stdin
    result = _run_script_in_bash(
        script,
        tmp_path,
        rc_on=_shell_words(BASH_STATEMENTS[1]),
    )

    assert result.returncode == 1


def test_meta_an_exit_zero_would_not_be_seen(tmp_path: Path) -> None:
    """The rc assertion of the session test bites.

    With ``builtin exit 0`` the script stops but the session looks
    successful, so the mutated script must not have the rc of the real
    one, or the rc assertion proves nothing.
    """
    script = vw.apply_script(BASH_STATEMENTS, 3).stdin
    mutated = script.replace("builtin exit 1", "builtin exit 0")
    assert mutated != script

    real = _run_script_in_bash(
        script, tmp_path, rc_on=_shell_words(BASH_STATEMENTS[1])
    )
    broken = _run_script_in_bash(
        mutated, tmp_path, rc_on=_shell_words(BASH_STATEMENTS[1])
    )

    assert real.returncode == 1
    assert broken.returncode == 0


def test_the_error_file_is_checked_before_the_first_statement() -> None:
    """A session that cannot make the error file stops at once.

    ``mktemp`` can fail (no temporary space, a read-only /tmp).  Then
    ``NEWTON_ERR`` is empty and every statement would write its stderr
    into a file that is not there: the guard would never fire and the
    apply would go on to the commit-confirm.  The script therefore checks
    the file right after ``mktemp`` and stops there.
    """
    for script in (
        vw.stage_script(STAGE_STATEMENTS).stdin,
        vw.apply_script(STAGE_STATEMENTS, 3).stdin,
    ):
        lines = script.splitlines()
        assert lines[2] == "NEWTON_ERR=$(mktemp)"
        assert lines[3] == MKTEMP_GUARD
        # the check is before the first statement
        assert lines.index(MKTEMP_GUARD) < lines.index(
            _statement_block(lines)[0]
        )
        # there is no trap: a trap is not usable in the vbash configure
        # mode, so the file is removed by the guards themselves
        assert "trap" not in script


def test_a_broken_mktemp_stops_the_apply(tmp_path: Path) -> None:
    """A ``mktemp`` that prints nothing stops the script.

    The emulation gives ``mktemp`` a function that prints nothing, so the
    error file cannot be made.  The script must stop before the first
    statement and before the commit-confirm.
    """
    script = vw.apply_script(BASH_STATEMENTS, 3).stdin
    result = _run_script_in_bash(script, tmp_path, empty_mktemp=True)

    assert "NEWTON-LINE-ERROR 0" in result.stdout
    assert "NEWTON-COMMIT-CONFIRM-CALLED" not in result.stdout
    assert "NEWTON-COMMITTED rc=0" not in result.stdout
    assert result.returncode == 1


def test_the_session_error_is_a_refusal() -> None:
    """"NEWTON-LINE-ERROR 0" is a refusal of the run.

    The zero is not a statement of the change: the session could not be
    prepared at all, so the run is refused with a message that says so
    and not with a message about a statement the device rejected.
    """
    from newton_mcp.vendor_change import VendorRefusal

    with pytest.raises(VendorRefusal, match="could not prepare the session"):
        vw.parse_stage("NEWTON-LINE-ERROR 0\n")
    with pytest.raises(VendorRefusal, match="could not prepare the session"):
        vw.parse_apply("NEWTON-LINE-ERROR 0\n")


def test_a_statement_error_is_not_a_session_refusal() -> None:
    """A statement that the device rejected is still a line error.

    The refusal of the listener test is for the session, not for the change: a
    statement the device refused is reported as the statement it is.
    """
    result = vw.parse_stage("NEWTON-LINE-ERROR 2\n")
    assert result.bad_line == 2
    assert result.ok is False
    assert vw.parse_apply("NEWTON-LINE-ERROR 2\n") == "line_error"


def test_the_session_error_refuses_the_stage() -> None:
    """The stage refuses the run when the session is not prepared.

    The refusal is the one the caller turns into the error the client
    sees, so it is raised where the output of the session is read.
    """
    from newton_mcp.vendor_change import RunOut, VendorRefusal

    def runner(_spec: Any) -> Any:
        return RunOut(status="ok", stdout="NEWTON-LINE-ERROR 0\n", stderr="",
                      exit_code=1)

    with pytest.raises(VendorRefusal, match="could not prepare the session"):
        vw.VyosOps().stage(
            runner, [["set", "system", "host-name", "p11-test"]]
        )


# ---- the writable leg of the error file guard ----------------------------
#
# The guard of the session has two legs: the name of the error file is not
# empty, and the file can be written into.  The second leg matters: a
# ``mktemp`` that names a file nobody can write leaves a name that is not
# empty, and every statement would then fail its redirect instead of
# writing its stderr into the file.  The session is not prepared, so the
# script has to stop there and not at a statement.


def test_an_unwritable_error_file_stops_the_apply(
    tmp_path: Path,
) -> None:
    """An error file that cannot be written stops the script."""
    script = vw.apply_script(BASH_STATEMENTS, 3).stdin
    result = _run_script_in_bash(script, tmp_path, readonly_mktemp=True)

    assert "NEWTON-LINE-ERROR 0" in result.stdout
    assert "NEWTON-LINE-ERROR 1" not in result.stdout
    assert "NEWTON-COMMIT-CONFIRM-CALLED" not in result.stdout
    assert "NEWTON-COMMITTED rc=0" not in result.stdout
    assert result.returncode == 1


def test_meta_the_writable_leg_is_what_stops_the_apply(
    tmp_path: Path,
) -> None:
    """Without the writable leg the stop is a statement error.

    The mutated guard keeps only the empty-name leg, so the script goes on
    to the first statement: its redirect cannot be made, the statement
    fails, and the error is the statement's.  The two runs must differ,
    or the CHR assertion proves nothing.
    """
    script = vw.apply_script(BASH_STATEMENTS, 3).stdin
    mutated = script.replace(
        'if [ -z "$NEWTON_ERR" ] || [ ! -w "$NEWTON_ERR" ]; then',
        'if [ -z "$NEWTON_ERR" ]; then',
    )
    assert mutated != script

    real = _run_script_in_bash(script, tmp_path, readonly_mktemp=True)
    broken = _run_script_in_bash(mutated, tmp_path, readonly_mktemp=True)

    assert "NEWTON-LINE-ERROR 0" in real.stdout
    assert "NEWTON-LINE-ERROR 0" not in broken.stdout
    assert "NEWTON-COMMIT-CONFIRM-CALLED" not in real.stdout
    assert "NEWTON-COMMIT-CONFIRM-CALLED" not in broken.stdout
