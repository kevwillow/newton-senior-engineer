"""Tests for the catalog-first secret redactor (K7)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

import pytest

from exhelp import explained, record_fields, record_fields_display

from newton_mcp import redact, server
from newton_mcp.envelope import is_envelope
from newton_mcp.plan import compute_plan_hash


def envelope_text(value):
    """Return the text payload of a value, unwrapping an envelope if needed."""
    if is_envelope(value):
        return value["text"]
    return value


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
BASE_HASH = "8" * 64

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "redact"
FIXTURE_FILES = [
    "wireless.txt",
    "network.txt",
    "ddns.txt",
    "rpcd.txt",
    "openvpn.auth",
    "shadow.txt",
    "key.pem",
]


SECRET_NEEDLES = {
    "wireless.txt": [
        r"fake-wpa2-shared-secret-passphrase",
        r"fake-wpa3-shared-secret-passphrase",
        r"fake-radius-shared-secret",
        r"fake-sae-shared-secret",
        r"fake-radius-acct-secret",
    ],
    "network.txt": [
        r"WGPRIVKEYa{34}=",
        r"WGPSKb{34}=",
        r"fake-pppoe-password-value",
    ],
    "ddns.txt": [
        r"fake-ddns-password-value",
    ],
    "rpcd.txt": [
        r"fake-rpcd-login-password-value",
    ],
    "openvpn.auth": [
        r"fake-openvpn-shared-secret-xyz123",
        r"fake-openvpn-token-value-abc456",
        r"fake-openvpn-tls-auth-static-key-value-789",
    ],
    "shadow.txt": [
        r"\$6\$fakesalt\$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
        r"\$5\$anothersalt\$zyxwvutsrqponmlkjihgfedcba9876543210ABCD",
        r"\$2y\$twicemoresalt\$MnbVCxYzAsDfGhJkLpQwErTyUiOpIsDfGhJkLzXcVb",
    ],
    "key.pem": [
        r"MIIEpAIBAAKCAQEA",
        r"0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
    ],
}


# ---- fixtures --------------------------------------------------------------

@pytest.fixture
def configured(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    redact.reset_key_cache()
    return tmp_path


@pytest.fixture
def configured_lab(tmp_path, monkeypatch):
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.quasar]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'profile = "lab"\nlab = true\n'
    )
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    redact.reset_key_cache()
    return tmp_path


def _record(**updates):
    record = {
        "device": "quasar",
        "host": "192.0.2.1",
        "session_id": SID,
        "uci_batch": "set system.@system[0].description='redaction test'",
        "diff": "system.@system[0].description='redaction test'",
        "probes": [["iface-absent", "guestx"]],
        "timeout_s": 90,
        "base_hash": BASE_HASH,
        "requires_approval": False,
        "router_digest": "d" * 64,
        **record_fields("set system.@system[0].description='redaction test'"),
        **record_fields_display(),
        "created_at": "2026-10-07T12:00:00+00:00",
        "staged_at": "2026-10-07T12:00:00+00:00",
    }
    record.update(updates)
    record["plan_hash"] = compute_plan_hash(record)
    return record


@pytest.fixture
def fresh_state(tmp_path, monkeypatch):
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path))
    redact.reset_key_cache()
    return tmp_path


# ---- catalog + path-based redaction ----------------------------------------

def test_redact_known_dotted_form_secret(fresh_state):
    out = redact.redact_text("wireless.default_radio0.key='hunter2pass'")
    assert "hunter2pass" not in out
    assert "<redacted:" in out
    assert out.endswith("'<redacted:" + out.split(":")[-1])


def test_redact_dotted_form_handles_indexed_section(fresh_state):
    out = redact.redact_text("rpcd.@login[0].password='$p$root'")
    assert "$p$root" not in out
    assert "<redacted:" in out


def test_redact_fail_closed_on_suffix(fresh_state):
    out = redact.redact_text("wireless.x.api_key='abcdef-secret-value'\nfoo.bar.baz_token='xyz-secret-value'")
    assert "abcdef-secret-value" not in out
    assert "xyz-secret-value" not in out
    assert out.count("<redacted:") == 2


def test_redact_file_form_option(fresh_state):
    text = "config wifi-iface 'default_radio0'\n\toption key 'fake-shared-secret'\n\toption mode 'ap'"
    out = redact.redact_text(text)
    assert "fake-shared-secret" not in out
    assert "option mode 'ap'" in out  # non-secret options left alone


def test_redact_file_form_handles_default_section(fresh_state):
    """An `option` line with no enclosing `config` still gets redacted (uses 'unknown' context)."""
    out = redact.redact_text("\toption key 'secret-value-fake'")
    assert "secret-value-fake" not in out


def test_redact_preserves_non_secret_options(fresh_state):
    out = redact.redact_text("wireless.default_radio0.ssid='VisibleNetworkName'\nwireless.default_radio0.mode='ap'")
    assert "VisibleNetworkName" in out
    assert "'ap'" in out


# ---- pattern-based redaction -----------------------------------------------

def test_redact_pem_block(fresh_state):
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAxxxxsecretxxxx\n-----END RSA PRIVATE KEY-----"
    out = redact.redact_text(text)
    assert "MIIEpAIBAAKCAQEAxxxxsecretxxxx" not in out
    assert "BEGIN RSA PRIVATE KEY" not in out


def test_redact_shadow_hash_dollar6(fresh_state):
    text = "root:$6$fakesalt$abcdefghijklmnopqrstuvwxyz0123456789.:18000:0:99999:7:::"
    out = redact.redact_text(text)
    assert "$6$fakesalt$" not in out
    assert "root:<redacted:" in out


def test_redact_shadow_hash_dollar5_dollar2y(fresh_state):
    out5 = redact.redact_text("user:$5$saltsalt$zyxwvutsrqponmlkjihgfedcba.:0:0:99999:7:::")
    out2y = redact.redact_text("bin:$2y$twosalt$abcdefghijklmnopqrstuvwxyzABCDEF.:0:0:99999:7:::")
    assert "$5$saltsalt$" not in out5
    assert "$2y$twosalt$" not in out2y


# ---- shadow-style crypt hashes redact the WHOLE field -----

@pytest.mark.parametrize(
    "shadow_line, raw_secret_substring",
    [
        # yescrypt: `$y$<params>$<salt>$<digest>` — four $ sections all redacted.
        (
            "root:$y$j9T$fakesaltfake$Abcdefghijklmnopqrstuvwxyz0123456789AB:19000:0:99999:7:::",
            "Abcdefghijklmnopqrstuvwxyz0123456789AB",
        ),
        # sha512crypt with explicit rounds= parameter.
        (
            "root:$6$rounds=5000$fakesalt$HASHHASHHASHHASHfakefakefakefake:19000:0:99999:7:::",
            "HASHHASHHASHHASHfakefakefakefake",
        ),
        # bcrypt: $2b$<cost>$<salt>$<hash>.
        (
            "root:$2b$12$fakesaltsaltsaltsaltsalt$ABCDEFGHIJKLMNOPQRSTUVWXYZabcde:19000::::::",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde",
        ),
        # md5: $1$<salt>$<hash>.
        (
            "root:$1$fakesalt$fakesecfakesecfakesecfak:0:0:99999:7:::",
            "fakesecfakesecfakesecfak",
        ),
        # 2a bcrypt (older variant).
        (
            "root:$2a$10$fakesaltsaltsaltsalt$ZZZfakefakefakefakefakefake:19000::::::",
            "ZZZfakefakefakefakefakefake",
        ),
    ],
)
def test_redact_shadow_hash_whole_field(fresh_state, shadow_line, raw_secret_substring):
    out = redact.redact_text(shadow_line)
    # The raw digest / hash substring is gone.
    assert raw_secret_substring not in out, f"raw digest leaked: {out!r}"
    # The whole `$id$...` field is gone (no stray `$id$` or salt left behind).
    assert "$y$j9T" not in out
    assert "$6$rounds=5000" not in out
    assert "$2b$12" not in out
    assert "$1$fakesalt" not in out
    assert "$2a$10" not in out
    # The shadow line still parses as a shadow line — `root:<redacted:...>:`.
    assert "root:<redacted:" in out
    assert ":" in out.split("root:<redacted:", 1)[1]


# ---- unterminated PEM block is redacted through to end of text -----

def test_redact_pem_unterminated_block(fresh_state):
    text = (
        "preamble\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAxxxxFAKEFAKEFAKEFAKE\n"
        "BBBBxxxxFAKEFAKEFAKEFAKE\n"
        "trailing-no-end"
    )
    out = redact.redact_text(text)
    # The BEGIN line, all base64 lines, and the trailing text are gone.
    assert "BEGIN PRIVATE KEY" not in out
    assert "MIIEpAIBAAKCAQEA" not in out
    assert "BBBBxxxxFAKEFAKEFAKEFAKE" not in out
    assert "trailing-no-end" not in out
    # The preamble survives and the whole redaction is a single placeholder.
    assert "preamble\n<redacted:" in out
    assert out.endswith(">")


# ---- case-insensitive names, contains rule, kv + list forms -----

@pytest.mark.parametrize(
    "name, line, raw_secret",
    [
        # Contains rule: key1..key4 match because of the contains-word rule.
        ("key1", "wireless.default_radio0.key1='hunter2hunter2'", "hunter2hunter2"),
        ("key2", "wireless.default_radio0.key2='hunter2hunter2'", "hunter2hunter2"),
        ("key3", "wireless.default_radio0.key3='hunter2hunter2'", "hunter2hunter2"),
        ("key4", "wireless.default_radio0.key4='hunter2hunter2'", "hunter2hunter2"),
        # Case-insensitive: capitalised "Key".
        ("Key upper", "wireless.default_radio0.Key='hunter2hunter2'", "hunter2hunter2"),
        # Contains psk: wpa_psk_file.
        ("wpa_psk_file", "wireless.x.wpa_psk_file='/etc/psk'", "/etc/psk"),
        # Contains private_key.
        ("private_key", "wg.x.private_key='hunter2hunter2'", "hunter2hunter2"),
        # Contains passphrase.
        ("wpa_passphrase", "wireless.x.wpa_passphrase='hunter2hunter2'", "hunter2hunter2"),
    ],
)
def test_redact_name_case_and_contains(fresh_state, name, line, raw_secret):
    out = redact.redact_text(line)
    assert raw_secret not in out, f"raw secret leaked via {name}: {out!r}"
    assert "<redacted:" in out


@pytest.mark.parametrize(
    "line, raw_secret",
    [
        # kv form: psk=...
        ("psk=hunter2hunter2", "hunter2hunter2"),
        # kv form: wpa_passphrase=...
        ("wpa_passphrase=hunter2hunter2", "hunter2hunter2"),
        # kv form with leading whitespace.
        ("\tpsk=hunter2hunter2", "hunter2hunter2"),
    ],
)
def test_redact_kv_form(fresh_state, line, raw_secret):
    out = redact.redact_text(line)
    assert raw_secret not in out, f"raw secret leaked via kv: {out!r}"
    assert "<redacted:" in out


def test_redact_kv_skips_non_secret_names(fresh_state):
    out = redact.redact_text("description=hello\nmode=ap")
    assert "description=hello" in out
    assert "mode=ap" in out


@pytest.mark.parametrize(
    "line, raw_secret, surrounding",
    [
        (
            "'set wireless.default_radio0.key='SuperSecretPass1'' is outside the approval-free set",
            "SuperSecretPass1",
            " is outside the approval-free set",
        ),
        (
            "uci: Parse error (invalid command) wireless.default_radio0.key='SuperSecretPass1' near line 4",
            "SuperSecretPass1",
            " near line 4",
        ),
        (
            "hostapd: using wpa_passphrase=SuperSecretPass1 for wlan0",
            "SuperSecretPass1",
            "",
        ),
        (
            "GET /cgi-bin/x?user=a&password=SuperSecretPass1&z=1",
            "SuperSecretPass1",
            "&z=1",
        ),
        (
            'set wireless.default_radio0.sae_password="Super Secret Pass1" ok',
            "Super Secret Pass1",
            " ok",
        ),
        (
            "add_list network.wg0.preshared_key=SuperSecretPass1",
            "SuperSecretPass1",
            "add_list ",
        ),
        (
            "diff: -wireless.default_radio0.key='SuperSecretPass1' was removed",
            "SuperSecretPass1",
            " was removed",
        ),
    ],
)
def test_redact_midline_secret_cases(fresh_state, line, raw_secret, surrounding):
    out = redact.redact_text(line)
    assert raw_secret not in out
    assert "<redacted:" in out
    if surrounding:
        assert surrounding in out


@pytest.mark.parametrize(
    "line",
    [
        "set wireless.default_radio0.ssid='LabNet' ok",
        "hostapd: channel=36 country=US",
        "uci: wireless.default_radio0.encryption='psk2' kept",
    ],
)
def test_redact_midline_non_secret_cases_unchanged(fresh_state, line):
    assert redact.redact_text(line) == line


@pytest.mark.parametrize(
    "line, raw_secret, expected_prefix",
    [
        (
            "error: wireless.default_radio0.key='ObviousFakeSecretTruncated",
            "ObviousFakeSecretTruncated",
            "error: wireless.default_radio0.key='",
        ),
        (
            'log: password="ObviousFakePasswordTruncated',
            "ObviousFakePasswordTruncated",
            'log: password="',
        ),
    ],
)
def test_redact_midline_unterminated_quote(
    fresh_state, line, raw_secret, expected_prefix
):
    out = redact.redact_text(line)
    assert raw_secret not in out
    assert out.startswith(expected_prefix + "<redacted:")
    assert out.endswith(">")


@pytest.mark.parametrize(
    "line, forbidden",
    [
        (
            "wireless.default_radio0.key=Super Secret Pass1",
            ("Super", "Secret", "Pass1"),
        ),
        ("wireless.default_radio0.key=abcSECRET,defSECRET", ("SECRET",)),
        ("wireless.default_radio0.key=abcSECRET;defSECRET", ("SECRET",)),
        ("wireless.default_radio0.key=abcSECRET&defSECRET", ("SECRET",)),
        ("wireless.default_radio0.key='abcSECRET' tailSECRET", ("SECRET",)),
        ("wireless.default_radio0.key='abSECRET'cdSECRET'", ("SECRET",)),
        ("wireless.default_radio0.key=abcSECRET defEND", ("SECRET", "END")),
        ("-wireless.default_radio0.key=abSECRET cdSECRET", ("SECRET",)),
        ("wpa_passphrase=my secretSECRET phraseEND", ("SECRET", "END")),
        ("password=abSECRET,cdSECRET", ("SECRET",)),
        ("psk=abSECRET;cdSECRET", ("SECRET",)),
        ("password=abSECRET&cdSECRET", ("SECRET",)),
        ("password='abSECRET'cdSECRET'", ("SECRET",)),
        ("secret=a'bSECRET", ("SECRET",)),
    ],
)
def test_redact_line_start_secret_consumes_whole_value(
    fresh_state, line, forbidden
):
    out = redact.redact_text(line)
    assert all(fragment not in out for fragment in forbidden)
    assert "<redacted:" in out


@pytest.mark.parametrize(
    "line",
    [
        "wireless.default_radio0.key='Super Secret Pass1'",
        "wireless.r0.key='Alpha'\\''Beta'",
        'wireless.default_radio0.sae_password="Super Secret Pass1"',
        "-wireless.default_radio0.key='Super Secret Pass1'",
    ],
)
def test_redact_midline_placeholder_equals_line_start(fresh_state, line):
    line_token = re.search(r"<redacted:[0-9a-f]{8}>", redact.redact_text(line))
    midline_token = re.search(
        r"<redacted:[0-9a-f]{8}>", redact.redact_text(f"pre {line} post")
    )
    assert line_token is not None
    assert midline_token is not None
    assert midline_token.group(0) == line_token.group(0)


def test_redact_midline_uci_escape_stays_in_single_quoted_value(fresh_state):
    text = "x 'set wireless.r0.key='AlphaSecret'\\''BetaSecret'' bad"
    out = redact.redact_text(text)
    assert "AlphaSecret" not in out
    assert "BetaSecret" not in out
    assert out.endswith(" bad")


def test_redact_midline_placeholders_unchanged(fresh_state):
    text = (
        "x wireless.default_radio0.key='<redacted:12345678>' y "
        "password=<redacted:12345678>&z=1"
    )
    assert redact.redact_text(text) == text


def test_redact_midline_is_idempotent_with_two_secrets(fresh_state):
    text = "x wireless.r0.key='FakeSecretOne' password=FakeSecretTwo end"
    once = redact.redact_text(text)
    assert redact.redact_text(once) == once


@pytest.mark.parametrize(
    "text, prefix",
    [
        ("x password=abcSECRET&n=1", "x password="),
        ("x?password=abcSECRET&n=1", "x?password="),
        ("user=root password=abcSECRET, shell=sh", "user=root password="),
        ("x key=aSECRET key2=bSECRET end", "x key="),
    ],
)
def test_redact_midline_unquoted_value_runs_to_line_end(
    fresh_state, text, prefix
):
    out = redact.redact_text(text)
    assert "SECRET" not in out
    assert out.startswith(prefix)
    assert "shell=sh" not in out
    assert "key2=bSECRET" not in out


def test_redact_midline_keeps_preceding_deletion_character(fresh_state):
    text = "see -wireless.default_radio0.key='SuperSecretPass1' gone"
    out = redact.redact_text(text)
    assert "SuperSecretPass1" not in out
    assert out.startswith("see -")
    assert out.endswith(" gone")


@pytest.mark.parametrize(
    "text, prefix",
    [
        ("x password=abcSECRET;n=1", "x password="),
        ('x password=abcSECRET"n=1', "x password="),
    ],
)
def test_redact_midline_unquoted_value_consumes_semicolon_and_quote(
    fresh_state, text, prefix
):
    out = redact.redact_text(text)
    assert "SECRET" not in out
    assert out.startswith(prefix)
    assert "n=1" not in out


@pytest.mark.parametrize(
    "text",
    [
        "x password='abcSECRET' y",
        'x password="abc SECRET" y',
    ],
)
def test_redact_midline_name_value_keeps_both_quotes(fresh_state, text):
    out = redact.redact_text(text)
    assert re.fullmatch(r"""x password=(['"])<redacted:[0-9a-f]{8}>\1 y""", out)


@pytest.mark.parametrize(
    "text",
    [
        "x wireless.r0.key='<redacted:12345678>TAILSECRET' y",
        "x password=<redacted:12345678>TAILSECRET y",
    ],
)
def test_redact_midline_placeholder_with_trailing_text_is_still_redacted(
    fresh_state, text
):
    assert "TAILSECRET" not in redact.redact_text(text)


@pytest.mark.parametrize(
    "text",
    [
        "a" * 200000,
        "a." * 100000,
        "a-" * 100000,
        ".".join(["tok"] * 3000),
    ],
)
def test_redact_midline_long_nonmatches_complete_quickly(fresh_state, text):
    started = time.perf_counter()
    out = redact.redact_text(text)
    elapsed = time.perf_counter() - started
    assert isinstance(out, str)
    assert elapsed < 10


def test_redact_file_form_list_directive(fresh_state):
    text = "config wifi-iface 'x'\n\tlist key 'hunter2hunter2'\n\tlist mode 'ap'"
    out = redact.redact_text(text)
    assert "hunter2hunter2" not in out
    assert "list mode 'ap'" in out
    assert "<redacted:" in out


# ---- JSON members whose name is secret-looking are redacted -----

@pytest.mark.parametrize(
    "json_text, raw_secret, secret_name",
    [
        # Single-line JSON, secret member.
        (
            '{"config": {"mode":"ap","ssid":"home","key":"hunter2hunter2"}}',
            "hunter2hunter2",
            "key",
        ),
        # Multi-line JSON, secret member on a later line.
        (
            '{\n\t"ssid": "home",\n\t"key": "hunter2hunter2",\n\t"sae_password": "abc"\n}',
            "hunter2hunter2",
            "key",
        ),
        # sae_password member on a later line.
        (
            '{\n\t"ssid": "home",\n\t"key": "hunter2hunter2",\n\t"sae_password": "abc"\n}',
            "\"sae_password\": \"abc\"",
            "sae_password",
        ),
        # private_key member (the value happens to be WireGuard-shaped).
        (
            '{"private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}',
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "private_key",
        ),
    ],
)
def test_redact_json_secret_member(fresh_state, json_text, raw_secret, secret_name):
    out = redact.redact_text(json_text)
    assert raw_secret not in out, f"raw secret leaked via json: {out!r}"
    # JSON is still valid: braces and the non-secret member stay.
    assert "{" in out and "}" in out
    # The secret member's *value* is the placeholder.
    assert f'"{secret_name}": "<redacted:' in out


def test_redact_json_preserves_non_secret_members(fresh_state):
    out = redact.redact_text(
        '{"ssid": "VisibleNetworkName", "mode": "ap", "encryption": "psk2"}'
    )
    assert '"ssid": "VisibleNetworkName"' in out
    assert '"mode": "ap"' in out
    assert '"encryption": "psk2"' in out
    assert "<redacted:" not in out


# ---- uci `'\''` escape is normalised before fingerprinting -----

def test_redact_uci_quote_escape_normalised_in_dotted(fresh_state):
    # uci quotes a value containing a single quote as: 'hunter2'\''hunter2'
    # The real value is hunter2'hunter2. Fingerprinting on the decoded form
    # means the escaped and unescaped forms give the same fingerprint.
    text_escaped = r"wireless.x.psk='hunter2'\''hunter2'"
    out = redact.redact_text(text_escaped)
    assert "hunter2" not in out
    fp = re.findall(r"<redacted:([0-9a-f]{8})>", out)
    assert len(fp) == 1
    expected = redact.fingerprint("wireless.x.psk", "hunter2'hunter2")
    assert fp[0] == expected


def test_redact_uci_quote_escape_normalised_in_file_form(fresh_state):
    text_escaped = "config wifi-iface 'x'\n\toption psk 'hunter2'\\''hunter2'\n"
    out = redact.redact_text(text_escaped)
    assert "hunter2" not in out
    fp = re.findall(r"<redacted:([0-9a-f]{8})>", out)
    assert len(fp) == 1
    expected = redact.fingerprint("@wifi-iface.x.psk", "hunter2'hunter2")
    assert fp[0] == expected


def test_redact_wireguard_44char_b64_key(fresh_state):
    b64 = "a" * 43 + "="  # exactly 44 chars, ends with '='
    assert len(b64) == 44 and b64.endswith("=")
    text = f"private_key={b64}"
    out = redact.redact_text(text)
    assert b64 not in out
    assert "<redacted:" in out


def test_redact_wireguard_skips_non_key_lines(fresh_state):
    b64 = "a" * 30 + "ABCDEFGHIJKLMNOPQ="
    text = f"this is just a comment that mentions the number {b64}"
    out = redact.redact_text(text)
    assert b64 in out  # line does not "name a key" → not redacted


# ---- test-gap T1: WireGuard pattern rule on its own -----------------------
# Mutation to catch: removing `text = _redact_wireguard(text, key, placeholder_fmt)`
# from redact_text(). Today's `key` / `password` / etc. catalog rules catch every
# WireGuard fixture first, so a freetext syslog line that *only* the WG
# keyword + b64 pattern can catch currently passes through uncaught by any test.


def test_redact_wireguard_pattern_catches_freetext_key_lines(fresh_state):
    b64 = "A" * 43 + "="  # 43 base64 characters plus the '=' padding
    assert len(b64) == 44 and b64.endswith("=")
    text = (
        f"Oct  7 12:00:00 netifd: wg0 private key {b64} loaded\n"
        f"peer key: {b64}\n"
    )
    out = redact.redact_text(text)
    assert b64 not in out, f"raw WG b64 key leaked through the pattern pass: {out!r}"
    assert "<redacted:" in out


# ---- test-gap T2: every catalog name (literal), in both forms ------------
# Mutation to catch: deleting "pin", "community" or "token" from
# KNOWN_SECRET_OPTIONS. Each of those names has no suffix / contains match,
# so removing it from the set makes the dotted form and the file form both
# drop them silently. The catalog list is written out literally below so a
# mutation cannot satisfy the test by editing the frozenset it imports.


@pytest.mark.parametrize(
    "name",
    [
        "key",
        "password",
        "passwd",
        "psk",
        "sae_password",
        "wpa_psk",
        "private_key",
        "preshared_key",
        "auth_secret",
        "priv_key_pwd",
        "secret",
        "token",
        "pin",
        "community",
        "foo_key",
        "foo_password",
        "foo_secret",
        "foo_psk",
        "foo_token",
    ],
)
def test_redact_catalog_covers_every_known_name_in_both_forms(fresh_state, name):
    value = f"obvious-fake-secret-for-{name}-xyz"
    # `uci show` dotted form: `<package>.<section>.<option>='<value>'`.
    dotted = f"pkg.sec.{name}='{value}'"
    out_dotted = redact.redact_text(dotted)
    assert value not in out_dotted, (
        f"raw secret leaked in dotted form for name {name!r}: {out_dotted!r}"
    )
    assert "<redacted:" in out_dotted
    # File form: an `option` line inside a `config` block.
    file_text = (
        f"config foo 'bar'\n"
        f"\toption {name} '{value}'\n"
        f"\toption mode 'ap'\n"
    )
    out_file = redact.redact_text(file_text)
    assert value not in out_file, (
        f"raw secret leaked in file form for name {name!r}: {out_file!r}"
    )
    assert "<redacted:" in out_file


# ---- new contains rules: token / community / uuid / pwd ----
# These compound names hold the four new contains-words (and the existing
# ``credential`` for good measure); both maskers must redact the value.


@pytest.mark.parametrize(
    "name",
    ["x_token_y", "my_community_z", "a_uuid_b", "the_pwd_value", "x_credential_y"],
)
def test_redact_new_contains_words_in_both_forms(fresh_state, name):
    value = f"obvious-fake-secret-for-{name}-xyz"
    dotted = f"pkg.sec.{name}='{value}'"
    out_dotted = redact.redact_text(dotted)
    assert value not in out_dotted, (
        f"raw secret leaked in dotted form for name {name!r}: {out_dotted!r}"
    )
    assert "<redacted:" in out_dotted
    file_text = (
        f"config foo 'bar'\n"
        f"\toption {name} '{value}'\n"
        f"\toption mode 'ap'\n"
    )
    out_file = redact.redact_text(file_text)
    assert value not in out_file, (
        f"raw secret leaked in file form for name {name!r}: {out_file!r}"
    )
    assert "<redacted:" in out_file


# ---- recursive value pass --------------------------------------------------

def test_redact_value_walks_dicts_and_lists(fresh_state):
    data = {
        "stdout": "wireless.default_radio0.key='hunter2pass'",
        "exit_code": 0,
        "log": [
            "private_key = " + "a" * 30 + "ABCDEFGHIJKLMNOPQ=",
            "noise line",
        ],
    }
    out = redact.redact_value(data)
    assert "hunter2pass" not in out["stdout"]
    b64 = "a" * 30 + "ABCDEFGHIJKLMNOPQ="
    assert b64 not in out["log"][0]
    assert out["log"][1] == "noise line"
    assert out["exit_code"] == 0


def test_redact_value_preserves_non_strings(fresh_state):
    assert redact.redact_value(42) == 42
    assert redact.redact_value(None) is None
    assert redact.redact_value(True) is True


# ---- fingerprint ------------------------------------------------------------

def test_fingerprint_stable_for_same_input(fresh_state):
    a = redact.fingerprint("wireless.default_radio0.key", "secret-value")
    b = redact.fingerprint("wireless.default_radio0.key", "secret-value")
    assert a == b
    assert re.fullmatch(r"[0-9a-f]{8}", a)


def test_fingerprint_differs_for_different_path(fresh_state):
    a = redact.fingerprint("wireless.a.key", "secret-value")
    b = redact.fingerprint("wireless.b.key", "secret-value")
    assert a != b


def test_fingerprint_differs_for_different_value(fresh_state):
    a = redact.fingerprint("wireless.a.key", "secret-value-1")
    b = redact.fingerprint("wireless.a.key", "secret-value-2")
    assert a != b


def test_key_persisted_0600_in_state_dir(fresh_state):
    redact.get_key()
    key_path = fresh_state / "redact.key"
    assert key_path.exists()
    assert oct(os.stat(key_path).st_mode & 0o777) == "0o600"


def test_existing_key_with_wrong_mode_raises(fresh_state):
    path = fresh_state / "redact.key"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x00" * 32)
    os.chmod(path, 0o644)
    redact.reset_key_cache()
    with pytest.raises(RuntimeError, match="0600"):
        redact.get_key()


# ---- placeholder preservation (round-trip) ---------------------------------

def test_redact_leaves_existing_placeholder_alone(fresh_state):
    fp = redact.fingerprint("wireless.default_radio0.key", "real-secret-value")
    text = f"wireless.default_radio0.key='<redacted:{fp}>'"
    out = redact.redact_text(text)
    assert out == text  # placeholder is preserved, not double-redacted


# ---- fixture corpus (every tool path) --------------------------------------

@pytest.mark.parametrize("filename", FIXTURE_FILES)
def test_fixture_redact_text_produces_no_raw_secrets(fresh_state, filename):
    text = (FIXTURES_DIR / filename).read_text()
    out = redact.redact_text(text)
    for needle in SECRET_NEEDLES[filename]:
        assert not re.search(needle, out), f"raw secret leaked from {filename}: {needle}"


@pytest.mark.parametrize("filename", FIXTURE_FILES)
def test_fixture_redact_value_produces_no_raw_secrets(fresh_state, filename):
    text = (FIXTURES_DIR / filename).read_text()
    wrapped = {"stdout": text, "stderr": text, "log": [text, "ok"], "ok": True, "n": 7}
    out = redact.redact_value(wrapped)
    serialized = json.dumps(out)
    for needle in SECRET_NEEDLES[filename]:
        assert not re.search(needle, serialized), f"raw secret leaked from {filename}: {needle}"


def _read_cp(text):
    return subprocess.CompletedProcess([], 0, text, text)


@pytest.mark.parametrize("filename", FIXTURE_FILES)
def test_newton_read_tool_path_no_raw_secrets(configured, monkeypatch, filename):
    text = (FIXTURES_DIR / filename).read_text()
    monkeypatch.setattr(
        server.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(args, 0, text, text),
    )
    result = server.newton_read("quasar", "uci show wireless")
    serialized = json.dumps(result)
    markers = {
        "wireless.txt": "LabNet",
        "network.txt": "127.0.0.1",
        "ddns.txt": "fake-host.example.test",
        "rpcd.txt": "newton",
        "openvpn.auth": "AES-256-CBC",
        "shadow.txt": "nobody:*",
    }
    assert result["exit_code"] == 0
    if filename in markers:
        assert markers[filename] in serialized
    assert "<redacted:" in serialized
    for needle in SECRET_NEEDLES[filename]:
        assert not re.search(needle, serialized), f"raw secret leaked via newton_read from {filename}: {needle}"


def test_newton_plan_tool_path_no_raw_secrets(configured, monkeypatch):
    text = (FIXTURES_DIR / "wireless.txt").read_text()
    plan_text = (
        "BACKUP /tmp/x.tar.gz (3 config files)\n"
        f"STAGED session={SID} from /tmp/x diff=hash\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 0 {'a' * 64}\n"
        "PROFILE lab\n"
        "APPROVAL not-required\n"
        f"PLANDIGEST {'d' * 64}\n"
        "----- diff -----\n"
        + text
        + "\n----------------\n"
    )
    monkeypatch.setattr(
        server.NewtonService, "run_script", lambda *a, **k: subprocess.CompletedProcess([], 0, plan_text, "")
    )
    planned = server.newton_plan_change("quasar", "set dhcp.x=host", **explained("set dhcp.x=host"))
    # the success path must run (without BASEHASH plan() fails and only the error envelope is checked)
    assert "error" not in planned
    assert planned["session_id"] == SID
    assert is_envelope(planned["diff"])
    serialized = json.dumps(planned)
    for needle in SECRET_NEEDLES["wireless.txt"]:
        assert not re.search(needle, serialized), f"raw secret leaked via newton_plan_change: {needle}"


def test_newton_plan_redacts_echoed_batch_secret_from_all_fields(
    configured, monkeypatch
):
    secret = "ObviousFakePlanSecret1"
    diff = f"wireless.default_radio0.key='{secret}'"
    plan_text = (
        "BACKUP /tmp/a.tar.gz (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 0 {'a' * 64}\n"
        "PROFILE lab\n"
        "APPROVAL not-required\n"
        f"PLANDIGEST {'d' * 64}\n"
        "----- diff -----\n"
        f"{diff}\n"
        "----------------\n"
    )
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], 0, plan_text, ""),
    )
    monkeypatch.setattr(
        server.NewtonService,
        "read",
        lambda self, d, c: {
            "exit_code": 1,
            "stdout": "",
            "stderr": "",
            "truncated": False,
        },
    )
    result = server.newton_plan_change(
        "quasar", f"set wireless.default_radio0.key='{secret}'", **explained(f"set wireless.default_radio0.key='{secret}'"),
    )
    assert secret not in json.dumps(result)
    assert result["approval_required"] is True
    assert result["approval_reasons"] == ["profile 'prod': every write requires approval"]


def test_newton_apply_tool_path_no_raw_secrets(configured_lab, monkeypatch):
    text = (FIXTURES_DIR / "wireless.txt").read_text()
    state = configured_lab / "state" / "plans"
    state.mkdir(parents=True)
    (state / f"{SID}.json").write_text(
        json.dumps(_record())
    )
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], 0, f"CONFIRMED session={SID}", text),
    )
    result = server.newton_apply_change("quasar", SID)
    assert result["result"] == "confirmed"
    assert is_envelope(result["log"])
    assert "<redacted:" in result["log"]["text"]
    serialized = json.dumps(result)
    for needle in SECRET_NEEDLES["wireless.txt"]:
        assert not re.search(needle, serialized), f"raw secret leaked via newton_apply_change: {needle}"


def test_newton_status_tool_path_no_raw_secrets(configured, monkeypatch):
    text = (FIXTURES_DIR / "wireless.txt").read_text()
    monkeypatch.setattr(
        server.NewtonService, "run_script", lambda *a, **k: subprocess.CompletedProcess([], 0, text, "")
    )
    result = server.newton_change_status("quasar", SID)
    serialized = json.dumps(result)
    for needle in SECRET_NEEDLES["wireless.txt"]:
        assert not re.search(needle, serialized), f"raw secret leaked via newton_change_status: {needle}"


def test_newton_abort_tool_path_no_raw_secrets(configured, monkeypatch):
    text = (FIXTURES_DIR / "wireless.txt").read_text()
    monkeypatch.setattr(
        server.NewtonService, "run_script", lambda *a, **k: subprocess.CompletedProcess([], 0, text, "")
    )
    result = server.newton_abort_change("quasar", SID)
    serialized = json.dumps(result)
    for needle in SECRET_NEEDLES["wireless.txt"]:
        assert not re.search(needle, serialized), f"raw secret leaked via newton_abort_change: {needle}"


def test_newton_backup_tool_path_no_raw_secrets(configured, monkeypatch):
    text = (FIXTURES_DIR / "wireless.txt").read_text()
    backup_line = "BACKUP /tmp/fake-backup.tar.gz (4 config files)\n"
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *a, **k: subprocess.CompletedProcess([], 0, backup_line + text, ""),
    )
    result = server.newton_backup("quasar")
    assert isinstance(result, dict)
    serialized = json.dumps(result)
    # The parsed result only exposes backup_path and config_files (per parse_backup);
    # the surrounding script text is discarded. A final redact_value pass still
    # covers any field a future implementation might add.
    assert "backup_path" in serialized and "config_files" in serialized
    for needle in SECRET_NEEDLES["wireless.txt"]:
        assert not re.search(needle, serialized), f"raw secret leaked via newton_backup: {needle}"


def test_call_tool_error_message_redacted(configured, monkeypatch):
    text = (FIXTURES_DIR / "wireless.txt").read_text()
    class FakeService:
        def list_devices(self):
            raise server.NewtonError(text)
    monkeypatch.setattr(server, "NewtonService", FakeService)
    result = server.call_tool("newton_list_devices", "-", lambda s: s.list_devices())
    serialized = json.dumps(result)
    for needle in SECRET_NEEDLES["wireless.txt"]:
        assert not re.search(needle, serialized), f"raw secret leaked via error path: {needle}"
    assert "<redacted:" in serialized


# ---- placeholder rule in plan() --------------------------------------------

def _plan_cp():
    return subprocess.CompletedProcess(
        [],
        0,
        (Path(__file__).parent / "fixtures" / "plan_output.txt").read_text(),
        "",
    )


def _call_plan(monkeypatch, run_script=None, read=None):
    monkeypatch.setattr(server.NewtonService, "run_script", run_script or (lambda *a, **k: _plan_cp()))
    if read is not None:
        monkeypatch.setattr(server.NewtonService, "read", read)
    return server.NewtonService().plan


def test_placeholder_drop_matching_fingerprint(configured_lab, monkeypatch):
    fp = redact.fingerprint("wireless.default_radio0.key", "real-secret-value")
    def read(self, d, c):
        if c == "uci get wireless.default_radio0.key":
            return {"exit_code": 0, "stdout": f"<redacted:{fp}>", "stderr": "", "truncated": False}
        return {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False}
    plan = _call_plan(monkeypatch, read=read)
    batch = (
        f"set wireless.default_radio0.key=<redacted:{fp}>\n"
        "set system.@system[0].description='cosmetic change'"
    )
    planned = plan("quasar", batch, **explained(batch))
    assert planned["approval_required"] is False
    assert "wireless.default_radio0.key" not in envelope_text(planned["diff"])


def test_placeholder_refuses_mismatched_fingerprint(configured, monkeypatch):
    def read(self, d, c):
        if c == "uci get wireless.default_radio0.key":
            return {"exit_code": 0, "stdout": "<redacted:deadbeef>", "stderr": "", "truncated": False}
        return {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False}
    plan = _call_plan(monkeypatch, read=read)
    fp = redact.fingerprint("wireless.default_radio0.key", "OTHER-VALUE")
    with pytest.raises(server.NewtonError, match="does not match"):
        plan("quasar", f"set wireless.default_radio0.key=<redacted:{fp}>", **explained(f"set wireless.default_radio0.key=<redacted:{fp}>"))


def test_placeholder_refused_in_non_set_verb(configured, monkeypatch):
    plan = _call_plan(monkeypatch)
    with pytest.raises(server.NewtonError, match="only be used"):
        plan("quasar", "delete wireless.default_radio0.key=<redacted:abcdef12>", **explained("delete wireless.default_radio0.key=<redacted:abcdef12>"))


def test_placeholder_refused_when_read_fails(configured, monkeypatch):
    read = lambda self, d, c: {
        "exit_code": 1,
        "stdout": "",
        "stderr": "not found",
        "truncated": False,
    }
    plan = _call_plan(monkeypatch, read=read)
    with pytest.raises(server.NewtonError, match="could not be read"):
        plan("quasar", "set wireless.default_radio0.key=<redacted:abcdef12>", **explained("set wireless.default_radio0.key=<redacted:abcdef12>"))


def test_placeholder_rule_uses_fingerprint_when_current_value_unredacted(configured_lab, monkeypatch):
    """When the current value at the path is a non-secret, the rule computes a fingerprint from the raw value."""
    raw = "this-is-not-a-secret-hostname"
    fp = redact.fingerprint("system.@system[0].hostname", raw)
    def read(self, d, c):
        if c == "uci get system.@system[0].hostname":
            return {"exit_code": 0, "stdout": raw, "stderr": "", "truncated": False}
        return {"exit_code": 1, "stdout": "", "stderr": "", "truncated": False}
    plan = _call_plan(monkeypatch, read=read)
    batch = (
        "set system.@system[0].hostname=<redacted:" + fp + ">\n"
        "set system.@system[0].description='cosmetic change'"
    )
    planned = plan("quasar", batch, **explained(batch))
    assert planned["approval_required"] is False


# ---- `uci get <pkg.section.option>` of a secret-looking option is redacted -----

def _fake_ssh_returning(stdout_text):
    def fake_run(args, **kw):
        return subprocess.CompletedProcess(args, 0, stdout_text, "")
    return fake_run


def test_uci_get_bare_secret_value_is_redacted(configured, monkeypatch):
    secret = "this-is-a-fake-wifi-key"
    monkeypatch.setattr(server.subprocess, "run", _fake_ssh_returning(secret + "\n"))
    svc = server.NewtonService()
    result = svc.read("quasar", "uci get wireless.default_radio0.key")
    stdout_text = envelope_text(result["stdout"])
    stderr_text = envelope_text(result["stderr"])
    assert secret not in stdout_text
    assert "<redacted:" in stdout_text
    assert stderr_text == ""


def test_uci_get_non_secret_option_not_redacted(configured, monkeypatch):
    value = "VisibleNetworkName"
    monkeypatch.setattr(server.subprocess, "run", _fake_ssh_returning(value + "\n"))
    svc = server.NewtonService()
    result = svc.read("quasar", "uci get wireless.default_radio0.ssid")
    stdout_text = envelope_text(result["stdout"])
    assert value in stdout_text
    assert "<redacted:" not in stdout_text


def test_uci_get_redacted_placeholder_drives_drop_in_plan(configured_lab, monkeypatch):
    """The full path: read() redacts a `uci get` secret value into <redacted:fp>; a subsequent
    plan() whose batch says `set <path>=<redacted:fp>` is accepted (line dropped)."""
    raw = "this-is-a-fake-wifi-key"
    fp = redact.fingerprint("wireless.default_radio0.key", raw)
    monkeypatch.setattr(server.subprocess, "run", _fake_ssh_returning(raw + "\n"))
    plan = _call_plan(monkeypatch)
    batch = f"set wireless.default_radio0.key=<redacted:{fp}>"
    planned = plan("quasar", batch, **explained(batch))
    assert planned["approval_required"] is False
    assert "wireless.default_radio0.key" not in envelope_text(planned["diff"])


# ---- exact placeholder form required (probe2 cases) -----

def _stub_read_returning(value):
    def read(self, d, c):
        return {"exit_code": 0, "stdout": value + "\n", "stderr": "", "truncated": False}
    return read


def _resolve_only(configured, monkeypatch, current_value):
    """Return a function that runs ONLY _resolve_placeholders against a bare NewtonService
    with read monkeypatched, like probe2 does. Uses the configured fixture for inventory."""
    monkeypatch.setattr(server.NewtonService, "read", _stub_read_returning(current_value))
    svc = server.NewtonService()
    return svc._resolve_placeholders


def test_accepts_unquoted_exact_placeholder(configured, monkeypatch):
    CUR = "hunter2hunter2"
    path = "wireless.default_radio0.key"
    fp = redact.fingerprint(path, CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"set {path}=<redacted:{fp}>"
    out = resolve("quasar", batch + "\n")
    assert "# dropped placeholder" in out
    assert path in out


def test_accepts_single_quoted_exact_placeholder(configured, monkeypatch):
    CUR = "hunter2hunter2"
    path = "wireless.default_radio0.key"
    fp = redact.fingerprint(path, CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"set {path}='<redacted:{fp}>'"
    out = resolve("quasar", batch + "\n")
    assert "# dropped placeholder" in out
    assert path in out


def test_accepts_double_quoted_exact_placeholder(configured, monkeypatch):
    CUR = "hunter2hunter2"
    path = "wireless.default_radio0.key"
    fp = redact.fingerprint(path, CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f'set {path}="<redacted:{fp}>"'
    out = resolve("quasar", batch + "\n")
    assert "# dropped placeholder" in out
    assert path in out


def test_refuses_placeholder_with_extra_text_in_quotes(configured, monkeypatch):
    CUR = "hunter2hunter2"
    path = "wireless.default_radio0.key"
    fp = redact.fingerprint(path, CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"set {path}='abc<redacted:{fp}>'"
    with pytest.raises(server.NewtonError, match="the value must be exactly one"):
        resolve("quasar", batch + "\n")


def test_refuses_placeholder_with_trailing_text(configured, monkeypatch):
    CUR = "hunter2hunter2"
    path = "wireless.default_radio0.key"
    fp = redact.fingerprint(path, CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"set {path}=<redacted:{fp}>extra"
    with pytest.raises(server.NewtonError, match="the value must be exactly one"):
        resolve("quasar", batch + "\n")


def test_refuses_placeholder_for_wrong_path(configured, monkeypatch):
    CUR = "hunter2hunter2"
    fp = redact.fingerprint("wireless.default_radio0.key", CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"set wireless.default_radio0.ssid=<redacted:{fp}>"
    with pytest.raises(server.NewtonError, match="does not match"):
        resolve("quasar", batch + "\n")


def test_refuses_placeholder_with_wrong_fingerprint(configured, monkeypatch):
    CUR = "hunter2hunter2"
    path = "wireless.default_radio0.key"
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"set {path}=<redacted:00000000>"
    with pytest.raises(server.NewtonError, match="does not match"):
        resolve("quasar", batch + "\n")


def test_refuses_placeholder_in_add_list(configured, monkeypatch):
    CUR = "hunter2hunter2"
    fp = redact.fingerprint("network.lan.dns", CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"add_list network.lan.dns=<redacted:{fp}>"
    with pytest.raises(server.NewtonError, match="only be used"):
        resolve("quasar", batch + "\n")


def test_refuses_placeholder_in_rename(configured, monkeypatch):
    CUR = "hunter2hunter2"
    path = "wireless.default_radio0.key"
    fp = redact.fingerprint(path, CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"rename {path}=<redacted:{fp}>"
    with pytest.raises(server.NewtonError, match="only be used"):
        resolve("quasar", batch + "\n")


def test_refuses_placeholder_in_set_space_form(configured, monkeypatch):
    CUR = "hunter2hunter2"
    path = "wireless.default_radio0.key"
    fp = redact.fingerprint(path, CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"set {path} <redacted:{fp}>"
    with pytest.raises(server.NewtonError, match="only be used"):
        resolve("quasar", batch + "\n")


def test_refuses_placeholder_for_a_different_unrelated_path(configured, monkeypatch):
    CUR = "hunter2hunter2"
    fp = redact.fingerprint("wireless.default_radio0.key", CUR)
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = f"set system.@system[0].hostname='<redacted:{fp}>'"
    with pytest.raises(server.NewtonError, match="does not match"):
        resolve("quasar", batch + "\n")


def test_lines_without_placeholder_pass_through(configured, monkeypatch):
    CUR = "this-is-not-a-secret"
    resolve = _resolve_only(configured, monkeypatch, CUR)
    batch = (
        "set dhcp.skilltest.0=host\n"
        "set dhcp.skilltest.0.name='skilltest'\n"
    )
    out = resolve("quasar", batch)
    assert out == batch  # no placeholders: lines kept verbatim


@pytest.mark.parametrize("marker", [
    "# dropped placeholder: nothing",
    "   # dropped placeholder: x",
])
def test_agent_cannot_supply_the_dropped_placeholder_marker(configured, monkeypatch, marker):
    """only Newton writes `# dropped placeholder:`; it counts as a change line."""
    plan = _call_plan(monkeypatch)
    batch = f"{marker}\nset system.@system[0].description='a'"
    with pytest.raises(server.NewtonError, match="dropped placeholder"):
        plan("quasar", batch, **explained(batch))
