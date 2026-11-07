from __future__ import annotations

import re
import time

import pytest

from newton_mcp import redact


SECRET = "ObviousFakeJsonSecret987"
KEY = b"k" * 32
PH = r"<redacted:[0-9a-f]{8}>"
BS = chr(92)

CONTAINER_SHAPES = [
    f'{{"psk": [["{SECRET}"]]}}',
    f'{{"psk": [{{"k": "{SECRET}"}}]}}',
    f'{{"psk": ["{SECRET}',
    f'{{"psk": ["a", "{SECRET}',
    f'{{"psk": [{SECRET}, 2]}}',
    f'{{"password": {{"value": "{SECRET}"}}}}',
    f'{{"key": ["{SECRET}", "b"]}}',
    '{"psk": [1, 2, 3]}',
    '{"key": {"a": {"b": ["x"]}}}',
    '{"key": ["a' + BS + '"b", "c"]}',
]


@pytest.mark.parametrize("text", CONTAINER_SHAPES)
def test_json_container_values_under_secret_names_are_redacted(text):
    out = redact.redact_text(text, KEY)
    assert SECRET not in out
    assert re.search(r'"(?:psk|password|key)": "<redacted:[0-9a-f]{8}>"', out)
    assert redact.redact_text(out, KEY) == out


def test_well_formed_neighbours_survive_container_redaction():
    out = redact.redact_text('{"psk": [["a"]], "mode": "ap"}', KEY)
    assert re.fullmatch(r'\{"psk": "<redacted:[0-9a-f]{8}>", "mode": "ap"\}', out)

    text = f'{{"a": {{"password": {{"v": "{SECRET}"}}}}, "ssid": "n"}}'
    out = redact.redact_text(text, KEY)
    assert '"ssid": "n"' in out
    assert SECRET not in out

    plain = '{"list": [1, 2], "x": {"y": 1}}'
    assert redact.redact_text(plain, KEY) == plain


ESCAPED_SHAPES = [
    pytest.param(f'{{"msg": "update failed password={BS}"{SECRET}{BS}" rc=1"}}', ("update failed", " rc=1"), id="json-msg-dq"),
    pytest.param(f'{{"msg": "set wireless.x.key={BS}"{SECRET}{BS}" ok"}}', (" ok",), id="json-set-dq"),
    pytest.param(f'x password={BS}"{SECRET} two{BS}" y', (" y",), id="text-dq"),
    pytest.param(f"x password='{SECRET}' y", (), id="text-sq-plain"),
    pytest.param(f"x password={BS}'{SECRET}{BS}' y", (" y",), id="text-sq-escaped"),
]


@pytest.mark.parametrize("text,words", ESCAPED_SHAPES)
def test_escaped_quote_openers_redact_the_body_and_keep_the_tokens(text, words):
    out = redact.redact_text(text, KEY)
    assert SECRET not in out
    assert "<redacted:" in out
    assert redact.redact_text(out, KEY) == out
    for w in words:
        assert w in out
    if BS + '"' in text:
        assert BS + '"<redacted:' in out
        assert re.search(r'<redacted:[0-9a-f]{8}>' + re.escape(BS + '"'), out)
    if BS + "'" in text:
        assert re.search(re.escape(BS + "'") + r'<redacted:[0-9a-f]{8}>' + re.escape(BS + "'"), out)


@pytest.mark.parametrize(
    "text",
    [
        "say " + BS + '"hello' + BS + '" and ' + BS + "'bye'" + BS + "'",
        "ssid=" + BS + '"Lab Net' + BS + '" mode=ap',
    ],
)
def test_text_with_escaped_quotes_but_no_secret_is_unchanged(text):
    assert redact.redact_text(text, KEY) == text


PERF_CASES = {
    "scalar_true": ('"key": true ' * 30000, '"key": true'),
    "scalar_number": ('"key": 1 ' * 30000, '"key": 1'),
    "array_flat": ('"key": [' + "1," * 30000 + "1]", '"key": ['),
    "array_nested": ('"key": [' + "[1]," * 30000 + "[1]]", '"key": ['),
    "object_deep": ('"key": {' * 30000, '"key": {'),
}


@pytest.mark.parametrize("label", list(PERF_CASES))
def test_json_scans_stay_fast_with_large_tail_filler(label):
    body, removed = PERF_CASES[label]
    text = body + "z" * 4_000_000
    started = time.perf_counter()
    out = redact.redact_text(text, KEY)
    elapsed = time.perf_counter() - started
    assert elapsed < 5, f"{label} took {elapsed:.1f}s"
    assert removed not in out
