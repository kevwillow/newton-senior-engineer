"""Redaction regressions."""

from __future__ import annotations

import re

import pytest

from newton_mcp import redact


KEY = b"SEC2-redaction-fixed-key!!!12345"
PLACEHOLDER = re.compile(r"<redacted:[0-9a-f]{8}>")
SESSION = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    "text, needles",
    [
        pytest.param(
            r'{"private-key": "S1", "wpa-psk":"S2"}',
            ("S1", "S2"),
            id="json-hyphenated-names",
        ),
        pytest.param(
            r'{"config":{"key":"S18","sae-password":"S19"}}',
            ("S18", "S19"),
            id="nested-json-hyphenated-name",
        ),
        pytest.param("private-key: S6", ("S6",), id="colon-private-key"),
        pytest.param("pre-shared-key: S8", ("S8",), id="colon-pre-shared-key"),
        pytest.param(
            "Authorization: Bearer abc9",
            ("Bearer", "abc9"),
            id="authorization-header",
        ),
        pytest.param(
            "x Proxy-Authorization: Basic Zm9vOmJhcg==",
            ("Basic", "Zm9vOmJhcg=="),
            id="midline-proxy-authorization-header",
        ),
        pytest.param(
            f"Cookie: sysauth_https={SESSION}; other=1",
            (SESSION, "other=1"),
            id="cookie-header-whole-value",
        ),
        pytest.param(
            f"ubus_rpc_session={SESSION}",
            (SESSION,),
            id="ubus-session-assignment",
        ),
        pytest.param(
            f'{{"ubus_rpc_session":"{SESSION}"}}',
            (SESSION,),
            id="ubus-session-json",
        ),
        pytest.param(f"sid: {SESSION}", (SESSION,), id="sid-colon"),
        pytest.param(f'{{"sid": "{SESSION}"}}', (SESSION,), id="sid-json"),
    ],
)
def test_s3_secret_name_spellings_and_headers_are_redacted(text, needles):
    out = redact.redact_text(text, KEY)
    for needle in needles:
        assert needle not in out, f"{needle!r} leaked: {out!r}"
    assert PLACEHOLDER.search(out)


@pytest.mark.parametrize(
    "text",
    [
        "ssid: HomeNet",
        r'{"ssid":"HomeNet"}',
        "wireless.ap.ssid='HomeNet'",
        "option ssid 'HomeNet'",
    ],
    ids=["colon", "json", "dotted", "file"],
)
def test_s3_network_names_are_not_secret(text):
    assert redact.redact_text(text, KEY) == text


def test_s3_secret_name_predicates_normalize_hyphens_and_case():
    for name in ("private-key", "WPA-PSK", "pre-shared-key", "SAE-Password"):
        assert redact._is_catalog_secret_name(name)
        assert redact._looks_like_secret_option(name)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "pending sid=0123456789abcdef0123456789abcdef "
            "guard=armed rpcd=ok config=ok boot=1a2b",
            id="p1-router-status",
        ),
        pytest.param(
            "Oct  1 12:00:00 router newton: cmd=apply "
            "sid=0123456789abcdef0123456789abcdef rc=0 from=10.0.0.5",
            id="p1-newton-syslog",
        ),
        pytest.param("x.y.sid='abc'", id="p1-uci-option"),
    ],
)
def test_p1_sid_name_value_forms_are_not_secret(text):
    assert redact.redact_text(text, KEY) == text


def test_p1_sid_status_survives_redact_value_envelope():
    status = (
        "pending sid=0123456789abcdef0123456789abcdef "
        "guard=armed rpcd=ok config=ok boot=1a2b"
    )
    assert redact.redact_value({"result": status}, KEY) == {"result": status}


@pytest.mark.parametrize(
    "text, needles, preserved",
    [
        pytest.param(
            "daemon[1]: key=Super Secret Pass1",
            ("Super", "Secret", "Pass1"),
            "daemon[1]: key=",
            id="unquoted-assignment",
        ),
        pytest.param(
            "daemon[1]: password: Super Secret",
            ("Super", "Secret"),
            "daemon[1]: password: ",
            id="unquoted-colon",
        ),
        pytest.param(
            "https://h/x?key=abc&ssid=Home",
            ("abc",),
            "ssid=Home",
            id="query-stops-at-separator",
        ),
        pytest.param(
            "daemon: key='a b' ssid=Home",
            ("a b",),
            "ssid=Home",
            id="quoted-value-stops-at-quote",
        ),
    ],
)
def test_s4_unquoted_midline_secret_value_runs_to_line_end(text, needles, preserved):
    out = redact.redact_text(text, KEY)
    for needle in needles:
        assert needle not in out, f"{needle!r} leaked: {out!r}"
    assert preserved in out
    assert PLACEHOLDER.search(out)


def test_s4_line_endings_and_trailing_spaces_are_preserved():
    text = "daemon: key=Super Secret  \r\nssid=Home\r\n"
    out = redact.redact_text(text, KEY)
    assert "Super" not in out and "Secret" not in out
    assert out.endswith("  \r\nssid=Home\r\n")


@pytest.mark.parametrize(
    "text",
    [
        "dhcp.@dnsmasq[0].authoritative='1'",
        "wireless.r.auth_server='192.0.2.1'",
        "wireless.r.auth_port='1812'",
        "wireless.r.auth_cache='1'",
        "wireless.r.acct_server='192.0.2.2'",
        "wireless.r.acct_port='1813'",
        "wireless.r.rsn_preauth='1'",
        "dropbear.d.MaxAuthTries='3'",
        "uhttpd.main.no_ubusauth='0'",
    ],
    ids=[
        "authoritative",
        "auth-server",
        "auth-port",
        "auth-cache",
        "acct-server",
        "acct-port",
        "rsn-preauth",
        "maxauthtries",
        "no-ubusauth",
    ],
)
def test_p3_catalog_allow_names_are_not_secret_options(text):
    assert redact.redact_text(text, KEY) == text


@pytest.mark.parametrize(
    "text, needle",
    [
        ("wireless.r.auth_secret='S1'", "S1"),
        ("network.w.auth='S2'", "S2"),
    ],
    ids=["auth-secret", "auth"],
)
def test_p3_real_auth_options_remain_secret(text, needle):
    out = redact.redact_text(text, KEY)
    assert needle not in out
    assert PLACEHOLDER.search(out)


@pytest.mark.parametrize(
    "text, needle",
    [
        ("ddns.x.param_enc='SECRET14'", "SECRET14"),
        ("option proxy_auth 'x15'", "x15"),
        ("proxy_auth: S1", "S1"),
        ("proxy-auth: S4", "S4"),
        ("Proxy_Auth: S5", "S5"),
        ("x.y.auth='S16'", "S16"),
        ("uhttpd.x.authdata='S17'", "S17"),
    ],
    ids=[
        "param-enc",
        "proxy-auth-option",
        "proxy-auth-colon",
        "proxy-auth-hyphen-colon",
        "proxy-auth-uppercase-colon",
        "exact-auth",
        "contains-auth",
    ],
)
def test_s5_catalog_gaps_are_redacted(text, needle):
    out = redact.redact_text(text, KEY)
    assert needle not in out, f"{needle!r} leaked: {out!r}"
    assert PLACEHOLDER.search(out)
