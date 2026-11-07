"""the approve screen must render blank-looking printable codepoints as
escapes, so an approver cannot read what the agent batch touches if it
relies on characters that look like nothing on their terminal.

The set of codepoints is the one ``newton_mcp.explanation`` already refuses
when the agent submits an explanation (they pass ``str.isprintable()`` but
render as nothing).  The host-side scanner at approve time has to escape
them too: the one set is shared between the two sites, not duplicated.

This file also covers the non-ASCII Zs codepoints (``U+00A0``, ``U+2003``,
``U+3000``, ``U+202F``) we verified: those are caught by
``str.isprintable()`` already, so they reach the escape branch without the
``BLANK_LOOKING`` set.  These tests prove the path, not just the data.
"""

from __future__ import annotations

import io
import inspect
import json
from datetime import datetime, timezone

import pytest

import newton_mcp.approve as approve
import newton_mcp.explanation as explanation
import newton_mcp.scans as scans
from exhelp import record_fields
from newton_mcp.plan import compute_plan_hash


SID = "0123456789abcdef0123456789abcdef"
DIGEST = "d" * 64
SCAN_REQUEST_ID = "0123456789abcdef0123456789abcdff"


# One codepoint from each group in ``BLANK_LOOKING``: chosen for
# coverage of every group, plus the five that start the set as a single
# shape ("five characters that print as nothing").  A parameterised test
# applies each to the three approve screens, so a regression in any one
# group fails the whole loop with a clear name.
# Note: characters beyond U+FFFF require the ``\U000NNNNN`` 8-digit
# escape in Python source; ``\uNNNN`` would truncate to a surrogate pair.
BLANK_CASES = [
    pytest.param("\u115f", id="U+115F-Hangul-Cho-Filler"),
    pytest.param("\u1160", id="U+1160-Hangul-Jung-Filler"),
    pytest.param("\u3164", id="U+3164-Hangul-Filler"),
    pytest.param("\uffa0", id="U+FFA0-Halfwidth-Hangul-Filler"),
    pytest.param("\u2800", id="U+2800-Braille-Pattern-Blank"),
    pytest.param("\u17b4", id="U+17B4-Khmer-Inherent-Vowel-Aa"),
    pytest.param("\u034f", id="U+034F-Combining-Grapheme-Joiner"),
    pytest.param("\ufffc", id="U+FFFC-Object-Replacement"),
    pytest.param("\u180b", id="U+180B-Mongolian-Free-Variation-Selector-One"),
    pytest.param("\ufe00", id="U+FE00-Variation-Selector-1"),
    pytest.param("\U000e0100", id="U+E0100-Variation-Selector-256"),
    pytest.param("\u180f", id="U+180F-Mongolian-FVS-Four"),
    pytest.param("\U0001d159", id="U+1D159-Null-Notehead"),
    pytest.param("\U00016fe4", id="U+16FE4-Khitan-Small-Script-Filler"),
    pytest.param("\U00013441", id="U+13441-Egyptian-Full-Blank"),
    pytest.param("\U00013442", id="U+13442-Egyptian-Half-Blank"),
]
# Non-ASCII Zs (Zs other than U+0020).  ``str.isprintable()`` is False for
# these, so they reach the existing \\uXXXX escape branch in
# ``_sanitize_terminal_value`` without touching the BLANK_LOOKING set.
# The test verifies the path still works for them.
NON_ASCII_ZS_CASES = [
    pytest.param("\u00a0", id="U+00A0-No-Break-Space"),
    pytest.param("\u2003", id="U+2003-Em-Space"),
    pytest.param("\u3000", id="U+3000-Ideographic-Space"),
    pytest.param("\u202f", id="U+202F-Narrow-No-Break-Space"),
]


def test_blank_looking_is_a_public_name_used_by_approve_and_explanation():
    # Contract: the blank-looking set is shared between the
    # agent-side validation (explanation.py) and the host-side
    # sanitiser (approve.py), so an oversight on one side is an
    # oversight on neither.  approve.py imports explanation as
    # ``_explanation`` and consults ``_explanation.BLANK_LOOKING``;
    # explanation.py uses ``BLANK_LOOKING`` itself.  Private copy (a
    # local frozenset in approve.py) would drift, so this test
    # rejects that by name; only the public module-level name is
    # acceptable.
    assert not hasattr(explanation, "_BLANK_LOOKING"), (
        "_BLANK_LOOKING is a private name; approve.py would have to "
        "reach into explanation internals.  Use the public name."
    )
    assert isinstance(explanation.BLANK_LOOKING, frozenset)
    for codepoint in ("\u115f", "\u1160", "\u3164", "\uffa0", "\u2800",
                      "\u17b4", "\u034f", "\ufffc", "\u180b", "\ufe00",
                      "\U000e0100"):
        assert codepoint in explanation.BLANK_LOOKING, codepoint
    # approve.py must read the set from the same module it imported,
    # not from a private symbol of its own.  ``_sanitize_terminal_value``
    # looks up BLANK_LOOKING through ``_explanation``; the test uses
    # source-text inspection so a future refactor (a local constant,
    # an alias) still fails fast if it loses the link.
    source = inspect.getsource(approve._sanitize_terminal_value)
    assert "_explanation.BLANK_LOOKING" in source, (
        "approve._sanitize_terminal_value must consult "
        "_explanation.BLANK_LOOKING; do not copy the literal."
    )


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


def plan_record(diff, *, sections=None):
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set wireless.radio0.country='CA'",
        "diff": diff,
        "probes": [["log-has", "present", "made-up-marker"]],
        "timeout_s": 120,
        "base_hash": "a" * 64,
        "requires_approval": True,
        "router_digest": DIGEST,
        **record_fields("set wireless.radio0.country='CA'"),
        "router_profile": "prod",
        "router_leash": ["mgmt-if"],
        "router_sections": sections if sections is not None else ["wireless.radio0"],
        "router_requires_approval": True,
        "staged_check": {"fw4": "skipped-untouched", "reason": "", "not_checked": ["firewall"]},
        "reasons": ["wireless configuration changes require approval"],
        "created_at": "2026-10-18T12:00:00+00:00",
        "staged_at": datetime.now(timezone.utc).isoformat(),
    }
    record["plan_hash"] = compute_plan_hash(record)
    return record


def write_plan(tmp_path, monkeypatch, record):
    state = tmp_path / "state"
    plans = state / "plans"
    plans.mkdir(parents=True)
    (plans / f"{SID}.json").write_text(json.dumps(record))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setenv("SUDO_USER", "labuser")
    return state


# --- direct unit tests for the sanitizer ---------------------------------


@pytest.mark.parametrize("character", BLANK_CASES)
def test_sanitize_terminal_value_escapes_blank_looking_characters(character):
    escaped = approve._sanitize_terminal_value(character)
    assert character not in escaped
    codepoint = ord(character)
    if codepoint <= 0xFFFF:
        assert escaped == f"\\u{codepoint:04x}"
    else:
        assert escaped == f"\\U{codepoint:08x}"


@pytest.mark.parametrize("character", BLANK_CASES)
def test_sanitize_terminal_value_escapes_blank_looking_inside_text(character):
    rendered = approve._sanitize_terminal_value(f"prefix-{character}-suffix")
    assert character not in rendered
    assert rendered.startswith("prefix-") and rendered.endswith("-suffix")
    codepoint = ord(character)
    needle = (
        f"\\u{codepoint:04x}"
        if codepoint <= 0xFFFF
        else f"\\U{codepoint:08x}"
    )
    assert needle in rendered


@pytest.mark.parametrize("character", NON_ASCII_ZS_CASES)
def test_sanitize_terminal_value_escapes_non_ascii_zs_characters(character):
    escaped = approve._sanitize_terminal_value(character)
    assert character not in escaped
    codepoint = ord(character)
    if codepoint <= 0xFF:
        assert escaped == f"\\x{codepoint:02x}"
    else:
        assert escaped == f"\\u{codepoint:04x}"


# --- (a) plan screen: diff line ------------------------------------------


@pytest.mark.parametrize("character", BLANK_CASES)
def test_approve_plan_screen_escapes_blank_looking_in_diff_line(
    tmp_path, monkeypatch, capsys, character
):
    diff = f"wireless.radio0.country='{character}CA{character}'"
    record = plan_record(diff=diff)
    write_plan(tmp_path, monkeypatch, record)
    monkeypatch.setattr(approve, "_getpass", lambda p: pytest.fail("getpass must not be called"))
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    code = approve.main([SID])
    out = capsys.readouterr()
    assert code == 1
    lines = out.out.splitlines()
    diff_idx = lines.index("Diff:")
    rendered_diff = "\n".join(lines[diff_idx + 1:])
    assert character not in rendered_diff, (
        f"blank-looking codepoint U+{ord(character):04X} reached the "
        "approve screen unescaped"
    )
    codepoint = ord(character)
    needle = (
        f"\\u{codepoint:04x}"
        if codepoint <= 0xFFFF
        else f"\\U{codepoint:08x}"
    )
    assert needle in rendered_diff
    # every printable character should remain printable (no other control
    # character slipped through by accident).
    assert all(
        ch.isprintable() or ch in " \\\n"
        for ch in out.out
    )


@pytest.mark.parametrize("character", NON_ASCII_ZS_CASES)
def test_approve_plan_screen_escapes_non_ascii_zs_in_diff_line(
    tmp_path, monkeypatch, capsys, character
):
    diff = f"wireless.radio0.country='{character}CA{character}'"
    record = plan_record(diff=diff)
    write_plan(tmp_path, monkeypatch, record)
    monkeypatch.setattr(approve, "_getpass", lambda p: pytest.fail("getpass must not be called"))
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    code = approve.main([SID])
    out = capsys.readouterr()
    assert code == 1
    assert character not in out.out, (
        f"non-ASCII Zs codepoint U+{ord(character):04X} reached the "
        "approve screen unescaped even though str.isprintable() is False"
    )
    codepoint = ord(character)
    if codepoint <= 0xFF:
        needle = f"\\x{codepoint:02x}"
    else:
        needle = f"\\u{codepoint:04x}"
    assert needle in out.out


# --- (b) plan screen: section name ---------------------------------------


@pytest.mark.parametrize("character", BLANK_CASES)
def test_approve_plan_screen_escapes_blank_looking_in_section_name(
    tmp_path, monkeypatch, capsys, character
):
    section = f"firewall.zone{character}.name=lan"
    record = plan_record(diff="firewall.zoneX.name='lan'", sections=[section])
    write_plan(tmp_path, monkeypatch, record)
    monkeypatch.setattr(approve, "_getpass", lambda p: pytest.fail("getpass must not be called"))
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    code = approve.main([SID])
    out = capsys.readouterr()
    assert code == 1
    assert character not in out.out, (
        f"section-line blank U+{ord(character):04X} reached the screen"
    )
    codepoint = ord(character)
    needle = (
        f"\\u{codepoint:04x}"
        if codepoint <= 0xFFFF
        else f"\\U{codepoint:08x}"
    )
    assert needle in out.out


# --- (c) scan approve screen: target -------------------------------------


@pytest.mark.parametrize("character", BLANK_CASES)
def test_approve_scan_screen_escapes_blank_looking_in_target(
    tmp_path, monkeypatch, capsys, character
):
    """a scan request whose ``target`` field carries a
    blank-looking codepoint must render escaped on the scan approve
    screen.

    ``scans._validate_request_fields`` rejects a target that is not an
    exact match for the parsed IPv4Address/IPv4Network, so a stored
    request never carries a blank-looking codepoint in its target
    today.  The precondition is a state-dir hand-edit that
    happens to land in the approvals path before ``_approve_scan``
    re-validates; we test the print path directly by monkey-patching
    ``scans.load_request`` to return a malformed request, the same way
    ``test_approve.py`` and ``test_scans.py`` inject fixtures when the
    full host pipeline is not what they need to exercise.
    """
    target = f"198.51.100.9{character}"
    malformed_request = {
        "id": SCAN_REQUEST_ID,
        "device": "router",
        "kind": "outside",
        "profile": "quick",
        "interface": "wan",
        "target": target,
        "vantage": "outside-a",
        "duration_cap_s": 300,
        "kept": "addresses and open TCP ports only",
        "created_at": "2026-10-18T12:00:00+00:00",
        "request_hash": "f" * 64,
    }
    monkeypatch.setattr(scans, "load_request", lambda state, request_id: malformed_request)
    monkeypatch.setattr(approve, "_getpass", lambda p: pytest.fail("getpass must not be called"))
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    code = approve.main([SCAN_REQUEST_ID])
    out = capsys.readouterr()
    assert code == 1
    assert character not in out.out + out.err, (
        f"scan-target blank U+{ord(character):04X} reached the screen"
    )
    codepoint = ord(character)
    needle = (
        f"\\u{codepoint:04x}"
        if codepoint <= 0xFFFF
        else f"\\U{codepoint:08x}"
    )
    target_line = next(
        line for line in out.out.splitlines() if line.startswith("Target:")
    )
    assert needle in target_line


# --- additional (c): blank-looking in other scan fields (sanity)


def test_approve_scan_screen_escapes_blank_looking_in_request_id(tmp_path, monkeypatch, capsys):
    """The scan approve screen also prints the ``request_id`` parameter
    (``Scan request:`` line) and the device name.  Both go through
    ``_sanitize_terminal_value`` and must escape a blank-looking byte
    that somehow landed there.  A literal call to ``approve.main`` with
    a non-32-hex id is refused by the outermost check
    (``PLAN_ID_RE.fullmatch``); the screen tests against ``request_id``
    that has shape but still reaches the sanitizer.  Monkey-patch
    ``load_request`` AND bypass the main() outer-shape check by calling
    ``approve._approve_scan`` directly with the sentinel-decorated id.
    """
    sentinel = "\u3164"
    bad_id = SCAN_REQUEST_ID.replace("c", sentinel, 1)
    target = "198.51.100.9"
    malformed_request = {
        "id": bad_id,
        "device": "router",
        "kind": "outside",
        "profile": "quick",
        "interface": "wan",
        "target": target,
        "vantage": "outside-a",
        "duration_cap_s": 300,
        "kept": "addresses and open TCP ports only",
        "created_at": "2026-10-18T12:00:00+00:00",
        "request_hash": "f" * 64,
    }
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    monkeypatch.setattr(scans, "load_request", lambda state, request_id: malformed_request)
    monkeypatch.setattr(approve, "_getpass", lambda p: pytest.fail("getpass must not be called"))
    monkeypatch.setattr(approve.sys, "stdin", TerminalInput("no\n"))
    code = approve._approve_scan(bad_id)
    out = capsys.readouterr()
    assert code == 1
    assert sentinel not in out.out + out.err
    assert "\\u3164" in out.out
