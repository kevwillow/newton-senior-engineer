from __future__ import annotations

import re
import time

import pytest

from newton_mcp import redact


SECRET = "ObviousFakeSecret987"
PH = r"<redacted:[0-9a-f]{8}>"


@pytest.mark.parametrize(
    "name",
    [
        "pass", "pwd", "pw", "pincode", "pin_code", "passphrase", "uuid",
        "credential", "credentials", "ro_community", "rw_community",
        "wps_pin", "auth_pass", "client_pwd", "login_pw", "node_uuid",
    ],
)
@pytest.mark.parametrize("form", ["dotted", "file"])
def test_catalog_additions_redact_dotted_and_file_names(name, form):
    text = (
        f"network.wan.{name}='{SECRET}'"
        if form == "dotted"
        else f"config interface 'wan'\n\toption {name} '{SECRET}'"
    )
    out = redact.redact_text(text, b"k" * 32)
    assert SECRET not in out
    assert "<redacted:" in out


@pytest.mark.parametrize(
    "name",
    ["bypass", "compass", "passthrough", "passive", "encryption", "ssid", "mode", "proto", "hostname", "timezone"],
)
def test_non_secret_name_negative_list_is_unchanged(name):
    text = f"system.x.{name}='{SECRET}'"
    assert redact.redact_text(text, b"k" * 32) == text


@pytest.mark.parametrize("operator", ["+=", "-=", "^="])
def test_list_edit_operators_are_preserved_and_redacted(operator):
    dotted = f"wireless.x.key{operator}'{SECRET}'"
    kv = f"prefix password{operator}{SECRET} suffix"
    dotted_out = redact.redact_text(dotted, b"k" * 32)
    kv_out = redact.redact_text(kv, b"k" * 32)
    assert operator in dotted_out and operator in kv_out
    assert SECRET not in dotted_out + kv_out


@pytest.mark.parametrize(
    "text, preserved",
    [
        (f"ddns.x.update_url='https://dynv6.example/api?hostname=h&token={SECRET}'", "hostname=h&token="),
        (f"ddns.x.update_url+='https://h.example/?token={SECRET}'", "update_url+='https://h.example/?token="),
        (f"system.x.notes='wireless.x.key={SECRET}'", "notes='wireless.x.key="),
        (f"wireless.x.ssid='key={SECRET}'", "ssid='key="),
        (f'logger: msg="update failed key={SECRET}" rc=1', 'msg="update failed key='),
        (f"option update_url 'https://dynv6.example/api?hostname=h&token={SECRET}'", "option update_url"),
        (f"acme.x.credentials='CF_Token={SECRET}'", "acme.x.credentials="),
        (f"msg='system.x.notes=wireless.x.key={SECRET}'", "wireless.x.key="),
    ],
)
def test_nested_assignments_inside_non_secret_values_are_scanned(text, preserved):
    out = redact.redact_text(text, b"k" * 32)
    assert SECRET not in out
    assert preserved in out


def test_url_userinfo_password_is_redacted_with_stable_path():
    text = f"update_url='https://user:{SECRET}@dyn.example/update'"
    out = redact.redact_text(text, b"k" * 32)
    expected = redact.fingerprint("url:userinfo", SECRET, b"k" * 32)
    assert out == f"update_url='https://user:<redacted:{expected}>@dyn.example/update'"


@pytest.mark.parametrize(
    "text, kept",
    [
        (f"x password={SECRET}&n=1", ""),
        (f"x password={SECRET},n=1 next", ""),
        (f"x password={SECRET};n=1 next", ""),
        (f"x?password={SECRET}&n=1", "&n=1"),
        (f'log key="ab\\\"{SECRET}" next', " next"),
        (f"log key='ab'{SECRET}' now", "'' now"),
        (f"log key='{SECRET}", ""),
    ],
)
def test_midline_value_extent_is_fail_closed(text, kept):
    out = redact.redact_text(text, b"k" * 32)
    assert SECRET not in out
    if kept:
        assert kept in out


def test_midline_value_tail_is_consumed_outside_url_query():
    out = redact.redact_text(f"x password={SECRET}&n=1", b"k" * 32)
    assert SECRET not in out
    assert "&n=1" not in out

    out = redact.redact_text(f"x password={SECRET},n=1 next", b"k" * 32)
    assert SECRET not in out
    assert ",n=1" not in out
    assert not out.endswith(" next")

    out = redact.redact_text(f"x password={SECRET};n=1 next", b"k" * 32)
    assert SECRET not in out
    assert ";n=1" not in out
    assert not out.endswith(" next")

    out = redact.redact_text(f"x?password={SECRET}&n=1", b"k" * 32)
    assert SECRET not in out
    assert "&n=1" in out


@pytest.mark.parametrize(
    "text",
    [
        f"Password: {SECRET}",
        f"key: {SECRET}",
        f"login failed, password: {SECRET} rejected",
    ],
)
def test_colon_secret_forms_redact(text):
    out = redact.redact_text(text, b"k" * 32)
    assert SECRET not in out
    assert re.search(PH, out)


@pytest.mark.parametrize(
    "text",
    [
        "Encryption: WPA2 PSK (CCMP)", "Mode: Master", "Signal: -52 dBm",
        "quasar:uci get x", "monkey: banana", "keystone: enabled",
        "Sat Oct 4 12:34:56 2026", "aa:bb:cc:dd:ee:ff",
        "password: <redacted:12345678>",
    ],
)
def test_strict_colon_predicate_leaves_device_text_unchanged(text):
    assert redact.redact_text(text, b"k" * 32) == text


@pytest.mark.parametrize(
    "text",
    [
        f'{{"key": "{SECRET}',
        '{"pin": 1234}',
        '{"psk": ["alpha","beta",17,true,null]}',
        f'{{"key": "ab\\\"{SECRET}"}}',
    ],
)
def test_json_secret_scalar_array_and_partial_forms(text):
    out = redact.redact_text(text, b"k" * 32)
    assert SECRET not in out
    assert re.search(r'"(?:key|pin|psk)": "<redacted:[0-9a-f]{8}>"', out)
    assert redact.redact_text(out, b"k" * 32) == out


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("k='" * 60000, id="k-quote-60000"),
        pytest.param("key='" * 60000, id="key-quote-60000"),
        pytest.param("a.b.c='" * 40000, id="dotted-quote-40000"),
        pytest.param("a.b.c+='" * 40000, id="dotted-plus-quote-40000"),
        pytest.param("http://" * 50000, id="http-60000"),
        pytest.param("http://u:p@" * 30000, id="http-userinfo-30000"),
        pytest.param("a" * 200000 + "://x:y@h", id="long-scheme-userinfo"),
    ],
)
def test_hostile_prefix_inputs_complete_under_ten_seconds(text):
    started = time.perf_counter()
    redact.redact_text(text, b"k" * 32)
    assert time.perf_counter() - started < 10


def test_new_value_forms_are_idempotent_and_plain_text_is_unchanged():
    plain = "ordinary status output with ssid mode proto hostname timezone"
    assert redact.redact_text(plain, b"k" * 32) == plain
    secret = f"log password: {SECRET}; wireless.x.key+='{SECRET}'"
    once = redact.redact_text(secret, b"k" * 32)
    assert redact.redact_text(once, b"k" * 32) == once
