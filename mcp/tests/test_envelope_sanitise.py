"""Tests for the output pipeline: envelope.sanitise_text / sanitise.

Every piece of device-originated text goes through this pipeline before it
is wrapped in the untrusted-device-data envelope.  The order is fixed by the
design (section 4 "Output pipeline, in order"):

    1. byte cap (only when max_bytes is set), partial last line dropped
    2. strip ANSI / OSC / other ESC plus C0 (except tab/newline) / C1 / DEL
    3. redact on the full text (caller-provided callable)
    4. mark every char with ord > 0x7E as \\u{<hex>}; escape literal
       backslash followed by `u{`; flag lines imitating Newton fields
    5. cap each line (LINE_CUT_SUFFIX when cut), then cap the whole field
    6. status empty / device_error / ok from error/success markers
    7. envelope(source, text)

"""

from __future__ import annotations

import subprocess

import pytest

import newton_mcp.envelope as _envelope
import newton_mcp.redact as _redact
import newton_mcp.server as _server


# A stub redactor used in the order tests.  It records every input it
# receives (so a test can assert what the pipeline fed it) and replaces
# the synthetic secret shape `password=<value>` with `password=<R>` where
# `<value>` runs until the next whitespace byte.
class StubRedactor:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, text: str) -> str:
        self.calls.append(text)
        out = []
        i = 0
        needle = "password="
        while True:
            j = text.find(needle, i)
            if j < 0:
                out.append(text[i:])
                break
            out.append(text[i:j + len(needle)])
            k = j + len(needle)
            while k < len(text) and not text[k].isspace():
                k += 1
            out.append("<R>")
            i = k
        return "".join(out)


def _identity_redactor(text: str) -> str:
    return text


def test_ansi_csi_osc_and_control_chars_removed():
    """ANSI CSI, OSC, lone ESC and C0/C1/DEL bytes are removed; tab/newline kept.

    The \\r overwrite case keeps both halves of the text (so the secret
    fragment before \\r is still visible to the redactor).
    """
    raw = (
        "\x1b[31mred\x1b[0m\t"           # CSI colour, tab kept
        "secret-ish\rSAFE\n"             # \r overwrite (both parts kept)
        "\x1b]0;evil title\x07line\n"    # OSC title terminated by BELL
        "\x1b]0;evil title\x1b\\line\n"  # OSC title terminated by ESC \\
        "\x1bXloose\n"                   # lone ESC + one char
        "\x00\x01\x07\x7f\x80\x9f\xff\n" # C0 (except tab/newline), DEL, C1, U+00FF
    )
    result = _envelope.sanitise_text(raw, redact=_identity_redactor)
    out = result.text
    # Tab and newline preserved.
    assert "\t" in out
    assert "\n" in out
    # No ANSI escape sequences left.
    for seq in ("\x1b[", "\x1b]", "\x1bX"):
        assert seq not in out
    # \r removed -> both halves visible.
    assert "secret-ish" in out and "SAFE" in out
    # C0/C1/DEL bytes removed.
    for bad in ("\x00", "\x01", "\x07", "\x7f", "\x80", "\x9f"):
        assert bad not in out
    # U+00FF (ord > 0x7E) was marked, not stripped.
    assert "\\u{ff}" in out
    # \r is removed (not replaced) so the halves join.
    assert "\r" not in out
    assert "secret-ishSAFE" in out
    # C1 bytes (U+0080..U+009F) are stripped in step 2 and never reach
    # the mark step, so no codepoint marker for them appears in output.
    assert "\\u{80}" not in out
    assert "\\u{9f}" not in out
    # The OSC payload is removed together with its ESC sequence.
    assert "evil title" not in out


def test_strip_rejoins_escape_split_token_for_redactor():
    """An ESC sequence inside a token makes the redactor see the rejoined form.

    The stub replaces `password=<value>` with `password=<R>` and records
    its input; we assert the secret value is gone and the recorded input
    had `password` joined (no \\x1b left) so the redaction actually fired.
    """
    raw = "noise\npass\x1b[0mword=hunter2xyz\nmore"
    stub = StubRedactor()
    result = _envelope.sanitise_text(raw, redact=stub)
    assert "hunter2xyz" not in result.text
    assert "password=<R>" in result.text
    # The redactor saw the rejoined form, not the raw ANSI-laden input.
    assert len(stub.calls) == 1
    assert "\x1b" not in stub.calls[0]
    assert "password=hunter2xyz" in stub.calls[0]


def test_non_ascii_chars_marked_exactly_no_nfkc():
    """Each non-ASCII codepoint becomes \\u{<lowercase hex, no leading zeros>}.

    In particular the ﬁ ligature (U+FB01) stays a single codepoint and is
    marked as \\u{fb01} -- never decomposed to `fi`.
    """
    raw = (
        "bidi=\u202e\n"               # U+202E RIGHT-TO-LEFT OVERRIDE
        "zwsp=\u200b\n"               # U+200B ZERO WIDTH SPACE
        "cyr=\u0430\n"                # U+0430 CYRILLIC SMALL LETTER A
        "full=\uff21\n"               # U+FF21 FULLWIDTH LATIN CAPITAL LETTER A
        "lig=\ufb01\n"                # U+FB01 LATIN SMALL LIGATURE FI
    )
    result = _envelope.sanitise_text(raw, redact=_identity_redactor)
    expected = (
        "bidi=\\u{202e}\n"
        "zwsp=\\u{200b}\n"
        "cyr=\\u{430}\n"
        "full=\\u{ff21}\n"
        "lig=\\u{fb01}\n"
    )
    assert result.text == expected


def test_literal_backslash_u_brace_escaped_to_marker():
    """A literal `\\u{202e}` in device text cannot fake a marker.

    The backslash that would otherwise open the marker syntax is itself
    marked as \\u{5c}; the rest of the sequence keeps going through the
    ordinary mark rule.
    """
    raw = "x\n\\u{202e}\ny\n"
    result = _envelope.sanitise_text(raw, redact=_identity_redactor)
    assert result.text == "x\n\\u{5c}u{202e}\ny\n"
    # And the (escaped) marker does not contain a stray `\u{202e}` that
    # a downstream consumer could mistake for a real codepoint marker.
    assert "\\u{202e}" not in result.text


def test_each_flag_trigger_flags_only_its_line():
    """Each trigger in the spec flags its own line; an ordinary line is not flagged.

    The triggers are the four substrings (case-insensitive) plus the
    word-boundary `\\bnewton\\b` and the anchored Newton-field regex.
    """
    triggers = [
        "x untrusted-device-data y",        # substring 1
        "device_role_enforced=true",         # substring 2
        "confirmation_id: abc",              # substring 3
        "this is T0-EXP territory",          # substring 4 (case-insensitive)
        "old newton logging",                # word `newton`
        "kind = 1",                          # anchored regex
        '"getter": foo',                     # quoted form of anchored regex
        '  tier="T0"',                       # whitespace + quoted form
        "caveat: experimental",              # bare keyword
        'certified = true',                  # bare keyword
    ]
    raw = "\n".join(triggers + ["interface eth0 up"]) + "\n"
    result = _envelope.sanitise_text(raw, redact=_identity_redactor)
    out_lines = result.text.split("\n")
    assert len(out_lines) == len(triggers) + 2  # blank trailing line after final \n
    for i, _ in enumerate(triggers):
        assert out_lines[i].startswith(_envelope.FLAG_PREFIX), (
            f"line {i} not flagged: {out_lines[i]!r}"
        )
    assert not out_lines[-2].startswith(_envelope.FLAG_PREFIX), (
        f"ordinary line should not be flagged: {out_lines[-2]!r}"
    )


def test_long_line_is_cut_short_line_unchanged():
    """A line longer than line_cap is cut and marked truncated.

    A short text is returned unchanged and truncated=False.
    """
    long_line = "a" * (_envelope.LINE_CAP + 100)
    raw = f"first\n{long_line}\nlast\n"
    result = _envelope.sanitise_text(raw, redact=_identity_redactor)
    out_lines = result.text.split("\n")
    assert result.truncated is True
    # Cut line: exactly line_cap chars + LINE_CUT_SUFFIX.
    assert len(out_lines[1]) == _envelope.LINE_CAP + len(_envelope.LINE_CUT_SUFFIX)
    assert out_lines[1].endswith(_envelope.LINE_CUT_SUFFIX)

    short = "alpha\nbeta\n"
    short_result = _envelope.sanitise_text(short, redact=_identity_redactor)
    assert short_result.truncated is False
    assert short_result.text == short


def test_field_cap_cuts_on_last_newline_boundary():
    """When the joined text exceeds field_cap, the partial last line is dropped."""
    line_len = 100
    raw = ("x" * line_len + "\n") * 7
    result = _envelope.sanitise_text(
        raw, redact=_identity_redactor, field_cap=500
    )
    assert result.truncated is True
    assert len(result.text) <= 500
    # Last char is a newline (kept boundary); no partial line.
    assert result.text.endswith("\n")
    # Every kept line is whole (no `xxx...x` fragment < 100).
    for line in result.text.split("\n")[:-1]:
        assert len(line) == line_len


def test_byte_cap_drops_partial_line_with_secret_and_handles_split_utf8():
    """max_bytes cut that falls inside a value drops the entire partial line.

    Multi-byte UTF-8 cut mid-codepoint does not raise (errors='replace').
    """
    head = "header line\n"               # 12 bytes
    raw_bytes = head.encode("utf-8") + b"password=hunter2xyz"
    cut_at = 26  # 12 + 14 -> cut inside `password=hunte`
    result = _envelope.sanitise_text(
        raw_bytes, redact=_identity_redactor, max_bytes=cut_at
    )
    assert result.truncated is True
    assert "hunter2" not in result.text
    assert "password" not in result.text
    assert "header line\n" in result.text

    # Str input with the same byte-cap also drops the partial last line.
    result_str = _envelope.sanitise_text(
        "header line\npassword=hunter2xyz",
        redact=_identity_redactor, max_bytes=cut_at,
    )
    assert result_str.truncated is True
    assert "hunter2" not in result_str.text
    assert "password" not in result_str.text
    assert "header line\n" in result_str.text

    # Partial multi-byte UTF-8 in bytes input must not raise: the byte
    # cap drops everything after the last \\n and the lone partial
    # sequence is decoded with errors="replace" and then marked.
    raw_bytes = b"ok\n\xe4\xb8\xad"  # 6 bytes; the last three are a complete 3-byte sequence
    result2 = _envelope.sanitise_text(
        raw_bytes, redact=_identity_redactor, max_bytes=4
    )
    # No exception; truncated is True (cut inside the partial sequence
    # with no later \\n -> the partial last line is dropped entirely).
    assert result2.truncated is True
    assert "ok" in result2.text
    # Replacement char from the dropped partial bytes does NOT leak into
    # the result text: the entire partial line was discarded.
    _U_REPLACEMENT = chr(0xFFFD)
    _REPL_MARKER = "\\u{fffd}"  # marked replacement char from the mark step
    assert _U_REPLACEMENT not in result2.text
    assert _REPL_MARKER not in result2.text

    # Partial UTF-8 in bytes input that is fully kept also does not
    # raise: it decodes via errors="replace" and the resulting
    # replacement char goes through the mark step.
    raw_bytes3 = b"\xe4\xb8"  # incomplete 3-byte sequence, kept whole
    result3 = _envelope.sanitise_text(raw_bytes3, redact=_identity_redactor)
    assert result3.text == _REPL_MARKER


def test_unclosed_pem_block_redacted_to_end():
    """An unclosed `-----BEGIN ... PRIVATE KEY-----` block is redacted to EOF.

    Runs through the real redact_text so the PEM rule is exercised.
    """
    raw = (
        "config ok\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "ABCDEF1234567890\n"
        "MORE_KEY_LINES\n"
    )
    result = _envelope.sanitise_text(
        raw,
        redact=_redact.redact_text,
        error_markers=(r"% Invalid input",),
    )
    assert "ABCDEF1234567890" not in result.text
    assert "MORE_KEY_LINES" not in result.text
    assert "<redacted:" in result.text
    assert result.status == "ok"
    assert "config ok" in result.text


def test_step_order_strip_redact_mark_cap():
    """Order: strip -> redact -> mark -> cap.

    The stub records the input it got.  We assert (a) the redactor saw the
    re-joined, non-ASCII-bearing text (no \\x1b), (b) the redactor saw raw
    non-ASCII (no marker), and (c) a secret past line_cap is redacted.
    The Cyrillic char is placed on its own line so it is not absorbed into
    the password value by the stub's whitespace-terminated match.
    """
    secret = "secretishvalue123"
    raw = (
        "pass\x1b[0mword=" + secret + "\n"
        + "\u0430\n"
        + ("x" * (_envelope.LINE_CAP + 50)) + "\n"
    )
    stub = StubRedactor()
    result = _envelope.sanitise_text(raw, redact=stub)
    # Secret value gone (redaction ran before cap).
    assert secret not in result.text
    assert "password=<R>" in result.text
    # Redactor saw the rejoined text (strip ran first).
    assert len(stub.calls) == 1
    assert "\x1b" not in stub.calls[0]
    assert "password=" + secret in stub.calls[0]
    # Redactor saw raw \u0430 (marking ran after redaction).
    assert "\\u{430}" not in stub.calls[0]
    assert "\u0430" in stub.calls[0]
    # Line past line_cap got cut -> truncated.
    assert result.truncated is True
    # The marked Cyrillic char survived (now as a marker) and the cut line
    # is exactly line_cap + LINE_CUT_SUFFIX chars.
    assert "\\u{430}" in result.text
    cut_line = result.text.split("\n")[2]
    assert len(cut_line) == _envelope.LINE_CAP + len(_envelope.LINE_CUT_SUFFIX)


def test_status_empty_ok_device_error_and_success_marker():
    """Status is empty / ok / device_error per the marker rules."""
    err_marker = r"% Invalid input detected"
    empty = _envelope.sanitise_text(
        "   \n\t  ", redact=_identity_redactor
    )
    assert empty.status == "empty"
    assert empty.text.strip() == ""

    ok = _envelope.sanitise_text(
        "all good\n", redact=_identity_redactor,
        error_markers=(err_marker,),
    )
    assert ok.status == "ok"

    bad = _envelope.sanitise_text(
        "uci: % Invalid input detected at 'foo'\n",
        redact=_identity_redactor, error_markers=(err_marker,),
    )
    assert bad.status == "device_error"

    miss = _envelope.sanitise_text(
        "nope\n",
        redact=_identity_redactor,
        success_marker=r"^OK$",
    )
    assert miss.status == "device_error"

    hit = _envelope.sanitise_text(
        "OK\n",
        redact=_identity_redactor,
        success_marker=r"^OK$",
    )
    assert hit.status == "ok"


def test_sanitise_returns_envelope_with_source():
    """sanitise() wraps the sanitised text with the given source."""
    out = _envelope.sanitise("quasar:version", "RouterOS 7.14\n", redact=_identity_redactor)
    assert _envelope.is_envelope(out.envelope)
    assert out.envelope["source"] == "quasar:version"
    assert out.envelope["text"] == "RouterOS 7.14\n"
    assert out.envelope["kind"] == _envelope.ENVELOPE_KIND
    assert out.status == "ok"
    assert out.truncated is False


def test_openwrt_read_passes_clean_text_and_strips_ansi(configured_newton, monkeypatch):
    """The OpenWrt read path uses sanitise_text now; ANSI is stripped, plain text round-trips.

    Plain ASCII uci output without secrets comes through byte-identical.
    ANSI in stdout is stripped.
    """
    plain = "network.wan=interface\nnetwork.wan.proto=dhcp\n"

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, plain, "")

    monkeypatch.setattr(_server.subprocess, "run", fake_run)
    result = _server.newton_read("quasar", "uci show network")
    assert result["exit_code"] == 0
    assert _envelope.is_envelope(result["stdout"])
    assert result["stdout"]["text"] == plain
    assert result["truncated"] is False

    ansi_stdout = "\x1b[32mwireless.default.radio0=device\x1b[0m\n"

    def fake_run_ansi(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, ansi_stdout, "")

    monkeypatch.setattr(_server.subprocess, "run", fake_run_ansi)
    result_ansi = _server.newton_read("quasar", "uci show wireless")
    assert result_ansi["stdout"]["text"] == "wireless.default.radio0=device\n"


def test_field_cap_without_newline_hard_cuts():
    """A single line over field_cap keeps field_cap chars (not emptied)."""
    result = _envelope.sanitise_text("y" * 600, redact=_identity_redactor, line_cap=10_000, field_cap=500)
    assert result.text == "y" * 500 and result.truncated is True


def test_field_anchor_regex_covers_envelope_and_result_fields():
    """The field-imitation flag covers envelope fields and the sanitise result keys.

    Names added beyond the first flag set (kind/getter/tier/caveat/certified):
    `source`, `text`, `status`, `truncated`, `data`, `device_role_enforced`.
    A line is flagged when EITHER a quoted field name is followed by
    whitespace and a colon (anywhere in the line) OR a bare/quoted name at
    line start is followed by `:` or `=`.  Word-ish names that only *start*
    with a protected word must NOT be flagged -- `"datapath": 1`,
    `metadata: x` and `database=1` all miss because the regex requires the
    closing quote/whitespace/separator to sit immediately after the
    protected name.
    """
    flagged = [
        '"status": "ok"',                  # quoted form, anywhere in line
        '  "text": "hi"',                  # leading whitespace + quoted
        '{"status": "ok", "caveat": "x"}',  # quoted forms mid-line
        'x, "source": "r1:cmd"',           # quoted form mid-line after comma
        'truncated = false',                 # bare form at line start, '='
    ]
    not_flagged = [
        '"datapath": 1',  # starts with `datapath`, not the word `data`
        'metadata: x',     # no quote; starts with `meta`, not `data`
        'database=1',      # starts with `database`; `base=` does not
                           # directly follow `data`, so (b) misses
        'interface eth0 up',  # ordinary line, no Newton field
    ]
    raw = "\n".join(flagged + not_flagged) + "\n"
    result = _envelope.sanitise_text(raw, redact=_identity_redactor)
    out_lines = result.text.split("\n")
    # Trailing empty line from the final "\n".
    assert len(out_lines) == len(flagged) + len(not_flagged) + 1
    for i, line in enumerate(flagged):
        assert out_lines[i].startswith(_envelope.FLAG_PREFIX), (
            f"expected flagged (line {i}): {line!r} -> {out_lines[i]!r}"
        )
    base = len(flagged)
    for j, line in enumerate(not_flagged):
        assert not out_lines[base + j].startswith(_envelope.FLAG_PREFIX), (
            f"expected NOT flagged (line {base + j}): {line!r} -> {out_lines[base + j]!r}"
        )
