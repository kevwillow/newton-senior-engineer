"""Platform redaction before the shared OpenWrt redactor."""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from newton_mcp import redact
from newton_mcp.adapters import platform_redact

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "vendors"


SECRET_WORDS = (
    "plaintext-password",
    "encrypted-password",
    "password",
    "pre-shared-secret",
    "secret",
    "shared-secret",
    "md5-key",
    "authentication-key",
    "private-key",
    "preshared-key",
    "community",
    "passphrase",
    "key",
)


def _assert_no_fragments(value: str, output: str) -> None:
    assert value not in output
    fragments = {
        value[start : start + 4] for start in range(len(value) - 3)
    }
    leaked = sorted(fragment for fragment in fragments if fragment in output)
    assert not leaked, f"leaked 4+ character fragments: {leaked}"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "add name=p1 wpa2-pre-shared-key=\\\n    Hunter2Synthetic\n",
            id="after-equals",
        ),
        pytest.param(
            "add name=p1 wpa2-pre-shared-key=Hunt\\\n    er2Synthetic\n",
            id="inside-value",
        ),
        pytest.param(
            'add name=p1 wpa2-pre-shared-key="Hun\\\r\n    ter2Synthetic"\n',
            id="inside-quoted-value-crlf",
        ),
        pytest.param(
            "add name=p1 \\\r\n    wpa2-pre-shared-key=Hunter2Synthetic\n",
            id="before-parameter-crlf",
        ),
    ],
)
def test_mv1_7_10_routeros_continuations_join_before_shared_redaction(
    text: str,
) -> None:
    """A RouterOS export wrap cannot split a secret across lines."""
    output = redact.redact_text(platform_redact.redact("routeros", text))
    _assert_no_fragments("Hunter2Synthetic", output)


def test_mv1_7_10_shared_redaction_alone_leaks_a_continuation() -> None:
    """Pin why RouterOS needs a platform pass before shared redaction."""
    text = "add name=p1 wpa2-pre-shared-key=\\\n    Hunter2Synthetic\n"
    output = redact.redact_text(text)
    assert "Hunter2Synthetic" in output


@pytest.mark.parametrize(
    "line",
    [
        "wpa2-pre-shared-key=RosWpa2Secret",
        "wpa-pre-shared-key=RosWpaSecret",
        'private-key="RosPrivateSecret"',
        "preshared-key=RosPresharedSecret",
        "authentication-password=RosAuthSecret",
        "encryption-password=RosEncryptionSecret",
        "password=RosPasswordSecret",
        "secret=RosSecretValue",
        "passphrase=RosPassphraseSecret",
        "auth-key=RosAuthKeySecret",
        "tcp-md5-key=RosTcpMd5Secret",
    ],
)
def test_mv1_7_11_routeros_name_value_forms_use_shared_redaction(
    line: str,
) -> None:
    """Hyphenated RouterOS name=value secrets are shared-redactor work."""
    output = redact.redact_text(platform_redact.redact("routeros", line))
    value = line.split("=", 1)[1].strip('"')
    assert value not in output
    assert line.split("=", 1)[0] in output


@pytest.mark.parametrize("word", SECRET_WORDS)
@pytest.mark.parametrize(
    "shape",
    ["bare", "single", "double", "unclosed-single", "unclosed-double", "tab", "uppercase"],
)
def test_mv1_7_12_vyos_secret_word_and_quote_shapes(word: str, shape: str) -> None:
    """Every VyOS secret word redacts every supported value shape."""
    value = "VySecretValue99"
    display = word.upper() if shape == "uppercase" else word
    separator = "\t" if shape == "tab" else " "
    texts = {
        "bare": f"set system {display}{separator}{value}",
        "single": f"set system {display}{separator}'{value}'",
        "double": f'set system {display}{separator}"{value}"',
        "unclosed-single": f"set system {display}{separator}'{value} tail",
        "unclosed-double": f'set system {display}{separator}"{value} tail',
        "tab": f"set system {display}{separator}{value}",
        "uppercase": f"set system {display}{separator}{value}",
    }
    output = platform_redact.redact("vyos", texts[shape])
    assert value not in output
    assert display in output
    shared_output = redact.redact_text(output)
    assert value not in shared_output


@pytest.mark.parametrize(
    "text",
    [
        "public-key AAAAsynthetic",
        "key-id 5",
        "set interfaces ethernet eth0 description uplink",
        "Version: VyOS 1.4",
    ],
)
def test_mv1_7_13_vyos_near_misses_are_unchanged(text: str) -> None:
    """Neighbours such as public-key and key-id are not secret words."""
    assert platform_redact.redact("vyos", text) == text


def test_mv1_7_14_platform_redaction_is_idempotent_and_keeps_placeholders() -> None:
    """Placeholders are terminal on both supported platforms."""
    routeros = (
        "add name=p1 password=\\\n    RouterSecret\n"
        "secret=<redacted:0a1b2c3d>\n"
        "passphrase=<redacted>\n"
    )
    vyos = (
        "set system password VyosSecret\n"
        "secret <redacted:0a1b2c3d>\n"
        "key <redacted>\n"
    )
    for platform, text in (("routeros", routeros), ("vyos", vyos)):
        once = platform_redact.redact(platform, text)
        twice = platform_redact.redact(platform, once)
        assert twice == once
        assert "<redacted:0a1b2c3d>" in twice
        assert "<redacted>\n" in twice


def test_mv1_7_15_openwrt_and_unknown_platforms_return_the_same_object() -> None:
    """OpenWrt remains byte-identical and unknown platforms opt out."""
    text = "password secretvalue\n\\\n    still-openwrt\n"
    assert platform_redact.redact("openwrt", text) is text
    assert platform_redact.redact("unknown-platform", text) is text


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("password " * 25_000, id="vyos-words-without-values"),
        pytest.param("\\\n    " * 40_000, id="routeros-continuations"),
    ],
)
def test_mv1_7_16_supported_rules_are_linear_time(text: str) -> None:
    """Neither platform rule may backtrack quadratically on 200 KB."""
    platform = "routeros" if text.startswith("\\") else "vyos"
    start = time.perf_counter()
    platform_redact.redact(platform, text)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"redact took {elapsed:.3f}s"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("password Hun{ter2X", id="open-brace-mid-value"),
        pytest.param("password Hun}ter2X", id="close-brace-mid-value"),
        pytest.param("password Hun;ter2X", id="semicolon-mid-value"),
        pytest.param("secret ab{cd}Hunter2X", id="braces-around-secret"),
    ],
)
def test_mv1_7_17_vyos_bare_value_stops_only_at_whitespace_or_quotes(
    text: str,
) -> None:
    """A VyOS secret value runs to whitespace or quote, not ``{};``."""
    output = redact.redact_text(platform_redact.redact("vyos", text))
    for fragment in ("ter2X", "Hun", "Hunter2X"):
        assert fragment not in output, fragment
    twice = redact.redact_text(platform_redact.redact("vyos", output))
    assert twice == output


def test_mv1_7_17_vyos_community_value_still_keeps_a_following_brace() -> None:
    """``community labro {`` still yields ``community <redacted> {``.

    The whitespace before ``{`` ends the bare-value run, so the brace is kept.
    """
    text = "community labro {"
    output = platform_redact.redact("vyos", text)
    assert output == "community <redacted> {"


# ---- Junos and Arista EOS platform redaction -------------

JUNOS_FORMS = (
    pytest.param(
        'authentication-key "$9$abcDEF123"; ## SECRET-DATA',
        id="auth-key-dollar-9-secret-data",
    ),
    pytest.param(
        'secret "$9$qwe";',
        id="secret-dollar-9",
    ),
    pytest.param(
        'encrypted-password "$6$abc$xyz"; ## SECRET-DATA',
        id="encrypted-password-dollar-6-secret-data",
    ),
    pytest.param(
        'pre-shared-key ascii-text "$9$zz"; ## SECRET-DATA',
        id="pre-shared-key-ascii-dollar-9-secret-data",
    ),
    pytest.param(
        'secret "PlainSynth55"; ## SECRET-DATA',
        id="secret-plain-secret-data-only",
    ),
    pytest.param(
        'set system root-authentication encrypted-password "$9$Q"',
        id="set-root-authentication-dollar-9",
    ),
    pytest.param(
        "community public;",
        id="community-bare-semicolon",
    ),
    pytest.param(
        "community public {",
        id="community-bare-brace",
    ),
    pytest.param(
        "set snmp community public authorization read-only",
        id="set-snmp-community-set-mode",
    ),
    pytest.param(
        "community JxComm42;",
        id="community-with-trailing-semicolon",
    ),
)

EOS_FORMS = (
    pytest.param(
        "username a secret 7 070C285F4D06",
        id="username-secret-type-7",
    ),
    pytest.param(
        "tacacs-server key 7 0822455D0A16",
        id="tacacs-server-key-type-7",
    ),
    pytest.param(
        "key-string 7 0822455D",
        id="key-string-type-7",
    ),
    pytest.param(
        "ip ospf message-digest-key 1 md5 7 0822AB",
        id="ospf-message-digest-key-with-keyid",
    ),
    pytest.param(
        "neighbor 192.0.2.1 password 7 0822AB",
        id="neighbor-bgp-password-type-7",
    ),
    pytest.param(
        "radius-server key 7 0822",
        id="radius-server-key-type-7",
    ),
    pytest.param(
        "enable secret sha512 $6$abc$def",
        id="enable-secret-sha512",
    ),
    pytest.param(
        "enable password 7 0822AB",
        id="enable-password-type-7",
    ),
    pytest.param(
        "ntp authentication-key 1 md5 7 0822AB",
        id="ntp-authentication-key-with-keyid",
    ),
    pytest.param(
        "snmp-server community s3cret ro",
        id="snmp-server-community-ro",
    ),
    pytest.param(
        "snmp-server community s3cret RO 10",
        id="snmp-server-community-ro-acl",
    ),
    pytest.param(
        "isis authentication key 7 0822AB",
        id="isis-authentication-key",
    ),
    pytest.param(
        "snmp-server community EosComm43 ro",
        id="snmp-server-community-named",
    ),
    pytest.param(
        "mac security profile x\n key 1234abcd 7 0A1B2C3D4E",
        id="macsec-key-ckn-type-value",
    ),
    pytest.param(
        "shared-key 7 SHK1Synthetic",
        id="shared-key-type-7",
    ),
    pytest.param(
        "pre-shared-key 7 PskSyn71Syn",
        id="pre-shared-key-type-7",
    ),
    pytest.param(
        "SECRET 7 Upper1Syn",
        id="secret-uppercase-type-7",
    ),
    pytest.param(
        "ip ospf authentication-key 7 OspfSyn71",
        id="ospf-authentication-key-type-7",
    ),
    pytest.param(
        "ip ospf authentication-key 0 OspfPlain72",
        id="ospf-authentication-key-type-0",
    ),
)


def _value_after_dollar9(line: str) -> str | None:
    """Extract the synthetic value after ``$9$`` in a Junos secret string."""
    match = re.search(r"\$9\$([^\"\s';]+)", line)
    return match.group(1) if match else None


def _value_after_dollar6(line: str) -> str | None:
    """Extract the synthetic value after ``$6$`` in a Junos secret string."""
    match = re.search(r"\$6\$([^\"\s';]+)", line)
    return match.group(1) if match else None


JUNOS_FORMS_EXTENDED = JUNOS_FORMS + (
    pytest.param(
        "pre-shared-key ascii-text \"$9$abcdQ\"; ## SECRET-DATA",
        id="pre-shared-key-ascii-dollar-9-quoted-after-label",
    ),
    pytest.param(
        "$9$FreeSyn81",
        id="bare-dollar-9-free-standing",
    ),
    pytest.param(
        "$8$Synth82",
        id="bare-dollar-8",
    ),
    pytest.param(
        '"$8$Synth83"',
        id="quoted-dollar-8",
    ),
)


def _value_after_dollar8(line: str) -> str | None:
    """Extract the synthetic value after ``$8$`` in a Junos secret string."""
    match = re.search(r"\$8\$([^\"\s\';]+)", line)
    return match.group(1) if match else None


@pytest.mark.parametrize("text", JUNOS_FORMS_EXTENDED)
def test_mv1_8_14_junos_forms_redact_synthetic_secrets(text: str) -> None:
    """Junos ``$9$/``$6$/``$1$/``## SECRET-DATA``/``community `` forms redact."""
    output = redact.redact_text(platform_redact.redact("junos", text))
    # Whole-string check: any value quoted between ``"`` must not survive.
    quoted = re.findall(r'"([^"\r\n]*)"', text)
    for inner in quoted:
        if not inner:
            continue
        assert inner not in output, f"leaked quoted value: {inner!r}"
    # 4+-character fragments after the ``$9$``/``$6$`` prefix must not leak.
    for extractor in (_value_after_dollar9, _value_after_dollar6, _value_after_dollar8):
        value = extractor(text)
        if not value or len(value) < 4:
            continue
        fragments = {value[start:start + 4] for start in range(len(value) - 3)}
        leaked = sorted(fragment for fragment in fragments if fragment in output)
        assert not leaked, f"leaked 4+ character fragments: {leaked}"
    # Bare ``$9$FreeSyn81`` / ``$8$Synth82`` / ``"$8$Synth83"`` / ``"$9$abcdQ"``
    # must be redacted even when the line is not flagged ``## SECRET-DATA``.
    for bare_value in ("abcdQ", "FreeSyn81", "Synth82", "Synth83"):
        if bare_value in text:
            assert bare_value not in output, f"leaked bare/quoted value: {bare_value!r}"
    # Bare ``community public;`` value must not survive as ``public``.
    if "community " in text:
        # Extract the value after ``community `` as a bare token (non-whitespace,
        # non-quote, non-{}, non-;).
        match = re.search(r"(?<![A-Za-z0-9_-])community[ \t]+([^{}\s\"';]+)", text)
        if match:
            assert match.group(1) not in output, match.group(0)


def _eos_secret_value(text: str) -> str:
    """Return the value the EOS regex redacts."""
    tokens = text.split()
    if tokens[:2] == ["snmp-server", "community"]:
        return tokens[2]
    return tokens[-1]


EOS_FORMS_MULTI = (
    pytest.param(
        "snmp-server user u g v3 auth sha 7 AUTHXprivSyn71 priv aes 7 PRIVYprivSyn72",
        id="snmp-user-auth-priv-type-7",
    ),
    pytest.param(
        "snmp-server user u g v3 auth sha AuthNoTypeSyn73 priv aes PrivNoTypeSyn74",
        id="snmp-user-auth-priv-no-type",
    ),
    pytest.param(
        "snmp-server user u g v3 localized 0011LocSyn75 auth sha AuthLocSyn76 priv aes PrivLocSyn77",
        id="snmp-user-localized-auth-priv",
    ),
)


@pytest.mark.parametrize("text", EOS_FORMS_MULTI)
def test_mv1_8_15_eos_multi_value_lines_redact_each_secret(text: str) -> None:
    """SNMPv3 ``user`` lines redact the value after ``auth`` AND after ``priv``."""
    output = redact.redact_text(platform_redact.redact("eos", text))
    forbidden = [
        "AUTHXprivSyn71", "PRIVYprivSyn72",
        "AuthNoTypeSyn73", "PrivNoTypeSyn74",
        "AuthLocSyn76", "PrivLocSyn77",
    ]
    for value in forbidden:
        assert value not in output, f"leaked EOS secret value: {value!r}"
    # The ``localized`` engine id token is not a secret; it must survive.
    if "0011LocSyn75" in text:
        assert "0011LocSyn75" in output, "lost localization engine id"
    # Idempotent
    twice = redact.redact_text(platform_redact.redact("eos", output))
    assert twice == output, f"not idempotent: {twice!r} != {output!r}"


@pytest.mark.parametrize("text", EOS_FORMS)
def test_mv1_8_15_eos_forms_redact_synthetic_secrets(text: str) -> None:
    """EOS ``secret/key/password/key-string/md5/authentication-key`` + snmp forms redact."""
    output = redact.redact_text(platform_redact.redact("eos", text))
    value = _eos_secret_value(text)
    assert value not in output, f"leaked EOS secret value: {value!r}"
    fragments = {value[start:start + 4] for start in range(len(value) - 3)}
    leaked = sorted(fragment for fragment in fragments if fragment in output)
    assert not leaked, f"leaked 4+ character fragments: {leaked}"
    # Type token (``0``/``5``/``7``/``8a``/``sha512``) and the leading keyword remain.
    keep_tokens = ("secret", "password", "key", "key-string", "md5",
                   "authentication-key", "snmp-server", "community",
                   "type", "0", "5", "7", "8a", "sha512")
    for token in keep_tokens:
        if token in text.split()[:-1]:
            assert token in output, f"lost label: {token!r}"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("ssh public-key AAAAsynthetic", id="eos-public-key"),
        pytest.param("key-id 5", id="eos-key-id"),
        pytest.param("Hostname: lab-mx", id="eos-hostname-line"),
        pytest.param("community-list Standard", id="eos-community-list"),
        pytest.param("snmp-server group g v3 auth", id="eos-snmp-group-no-user"),
        pytest.param("aaa authentication login default local", id="eos-aaa-login-local"),
        pytest.param("ip ospf authentication message-digest", id="eos-ospf-auth-message-digest"),
    ],
)
def test_mv1_8_16_eos_near_misses_are_unchanged(text: str) -> None:
    """EOS neighbours (public-key, key-id, Hostname:, community-list) stay."""
    assert platform_redact.redact("eos", text) == text


@pytest.mark.parametrize(
    "fixture_path",
    [
        pytest.param(p, id=p.name)
        for p in sorted((FIXTURES_DIR / "eos").iterdir())
        if p.is_file() and "error" not in p.name
    ],
)
def test_mv1_8_16_eos_enabled_getter_fixtures_byte_identical(
    fixture_path: Path,
) -> None:
    """Shipped EOS non-error fixtures are byte-identical after redaction."""
    text = fixture_path.read_text(encoding="utf-8")
    assert platform_redact.redact("eos", text) == text


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("ssh public-key AAAAsynthetic", id="junos-public-key"),
        pytest.param("key-id 5", id="junos-key-id"),
        pytest.param("Hostname: lab-mx", id="junos-hostname-line"),
        pytest.param("community-list Standard", id="junos-community-list"),
    ],
)
def test_mv1_8_16_junos_near_misses_are_unchanged(text: str) -> None:
    """Junos neighbours (public-key, key-id, Hostname:) stay."""
    assert platform_redact.redact("junos", text) == text


@pytest.mark.parametrize(
    "fixture_path",
    [
        pytest.param(p, id=p.name)
        for p in sorted((FIXTURES_DIR / "junos").iterdir())
        if p.is_file() and "error" not in p.name
    ],
)
def test_mv1_8_16_junos_enabled_getter_fixtures_byte_identical(
    fixture_path: Path,
) -> None:
    """Shipped Junos non-error fixtures are byte-identical after redaction."""
    text = fixture_path.read_text(encoding="utf-8")
    assert platform_redact.redact("junos", text) == text


def test_mv1_8_17_junos_idempotence_and_placeholders() -> None:
    """Junos redaction is idempotent and keeps existing placeholders."""
    text = (
        'authentication-key "$9$JxSynth41"; ## SECRET-DATA\n'
        'encrypted-password "$6$abc$xyz"; ## SECRET-DATA\n'
        'pre-shared-key ascii-text "$9$zz"; ## SECRET-DATA\n'
        'community JxComm42;\n'
        'community JxHolder { authorization read-only; }\n'
        'snmp community JxHolderSet authorization read-only\n'
        'community <redacted:0a1b2c3d>;\n'
        'authentication-key "<redacted:0a1b2c3d>"; ## SECRET-DATA\n'
    )
    once = redact.redact_text(platform_redact.redact("junos", text))
    twice = redact.redact_text(platform_redact.redact("junos", once))
    assert twice == once
    for fragment in ("JxSynth41", "JxComm42", "JxHolder", "JxHolderSet",
                     "$9$abc", "$6$abc"):
        assert fragment not in once, f"leaked: {fragment}"
    assert "<redacted:0a1b2c3d>" in once
    # Pin the placeholder line byte-identical.
    assert 'authentication-key "<redacted:0a1b2c3d>"; ## SECRET-DATA' in once


def test_mv1_8_17_eos_idempotence_and_placeholders() -> None:
    """EOS redaction is idempotent and keeps existing placeholders."""
    text = (
        "username a secret 7 070C285F4D06\n"
        "tacacs-server key 7 0822455D0A16\n"
        "ntp authentication-key 1 md5 7 0822AB\n"
        "snmp-server community s3cret ro\n"
        "secret 7 <redacted:0a1b2c3d>\n"
        "community <redacted>\n"
        "snmp-server community <redacted:0a1b2c3d> ro\n"
        "key <redacted> 7 <redacted>\n"
        "snmp-server user u g v3 auth sha 7 <redacted> priv aes 7 <redacted>\n"
    )
    once = redact.redact_text(platform_redact.redact("eos", text))
    twice = redact.redact_text(platform_redact.redact("eos", once))
    assert twice == once
    for fragment in ("070C285F4D06", "0822455D0A16", "0822AB", "s3cret"):
        assert fragment not in once, f"leaked: {fragment}"
    assert "<redacted:0a1b2c3d>" in once
    assert "secret 7 <redacted:0a1b2c3d>" in once
    # Pin the placeholder lines byte-identical.
    assert "snmp-server community <redacted:0a1b2c3d> ro" in once
    assert "key <redacted> 7 <redacted>" in once
    assert (
        "snmp-server user u g v3 auth sha 7 <redacted> priv aes 7 <redacted>"
        in once
    )


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(("eos", "secret 7 " * 25_000), id="eos-secret-type-without-value"),
        pytest.param(("junos", '"$9$' * 25_000), id="junos-unclosed-dollar-9-quotes"),
        pytest.param(
            ("eos", "snmp-server user u auth sha " * 25_000),
            id="eos-snmp-user-line-stress",
        ),
        pytest.param(
            ("eos", "key a 7 " * 25_000),
            id="eos-macsec-key-stress",
        ),
        pytest.param(
            ("eos", "authentication text " * 12_000),
            id="eos-vrrp-text-auth-stress",
        ),
        pytest.param(
            ("eos", "snmp-server host h version 2c " * 13_500),
            id="eos-snmp-host-version-2c-stress",
        ),
        pytest.param(
            ("eos", "snmp-server host " + "h vrf v traps " * 15_000),
            id="eos-snmp-host-bare-stress",
        ),
    ],
)
def test_mv1_8_18_junos_and_eos_rules_are_linear_time(
    text: tuple[str, str],
) -> None:
    """Each new platform rule stays linear on 200 KB of stress input."""
    platform, body = text
    start = time.perf_counter()
    platform_redact.redact(platform, body)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"redact took {elapsed:.3f}s"


@pytest.mark.parametrize(
    ("text", "secrets"),
    [
        pytest.param("Snmp-Server Community MixSyn44 ro", ("MixSyn44",), id="snmp-community-mixed-case"),
        pytest.param("SNMP-SERVER USER u g v3 AUTH sha 7 MixAuth78 PRIV aes 7 MixPriv79",
                     ("MixAuth78", "MixPriv79"), id="snmp-user-upper-case"),
    ],
)
def test_mv1_8_22_eos_snmp_rules_ignore_case(text: str, secrets: tuple[str, ...]) -> None:
    """The EOS snmp-server community and user rules match any case, like the other EOS rules."""
    output = redact.redact_text(platform_redact.redact("eos", text))
    for value in secrets:
        assert value not in output, f"leaked EOS secret value: {value!r}"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "vrrp 1 peer authentication text 7 VRRP7ENC",
            "vrrp 1 peer authentication text 7 <redacted>",
            id="vrrp-text-auth-type-7",
        ),
        pytest.param(
            "vrrp 1 peer authentication text VRRPTXT",
            "vrrp 1 peer authentication text <redacted>",
            id="vrrp-text-auth-bare",
        ),
        pytest.param(
            "VRRP 1 PEER AUTHENTICATION TEXT 7 VrrpUp1",
            "VRRP 1 PEER AUTHENTICATION TEXT 7 <redacted>",
            id="vrrp-text-auth-upper-case-type-7",
        ),
    ],
)
def test_mv1_8_23_eos_vrrp_text_authentication_redacts_value(
    text: str, expected: str
) -> None:
    """VRRP ``authentication text`` (with optional type 0|7) redacts the value."""
    once = redact.redact_text(platform_redact.redact("eos", text))
    assert once == expected
    # Idempotent.
    twice = redact.redact_text(platform_redact.redact("eos", once))
    assert twice == once


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "snmp-server host 10.0.0.1 version 2c TRAPCOMM",
            id="snmp-host-v2c-bare",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 informs version 2c TrapInf2 udp-port 162",
            id="snmp-host-informs-v2c",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 vrf MGMT version 1 TrapV1x",
            id="snmp-host-vrf-v1",
        ),
        pytest.param(
            "Snmp-Server Host 10.0.0.1 Version 2C TrapUp2",
            id="snmp-host-mixed-case-v2c",
        ),
    ],
)
def test_mv1_8_24_eos_snmp_host_version_1_or_2c_redacts_community(
    text: str,
) -> None:
    """``snmp-server host ... version 1|2c <value>`` redacts the community."""
    once = redact.redact_text(platform_redact.redact("eos", text))
    for fragment in ("TRAPCOMM", "TrapInf2", "TrapV1x", "TrapUp2"):
        if fragment in text:
            assert fragment not in once, f"leaked: {fragment}"
    # The trailing tokens (udp-port, vrf name) and v2c/v1 type token are kept.
    import re as _re
    version_match = _re.search(r"(?i)version[ \t]+(?:1|2c)[ \t]+<redacted>", once)
    assert version_match is not None, once
    if "udp-port" in text:
        assert "udp-port 162" in once
    if "vrf MGMT" in text:
        assert "vrf MGMT" in once
    # Idempotent.
    twice = redact.redact_text(platform_redact.redact("eos", once))
    assert twice == once


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "snmp-server host 10.0.0.1 version 3 auth monitorUser",
            id="snmp-host-v3-auth-user-untouched",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 version 3 priv u3",
            id="snmp-host-v3-priv-user-untouched",
        ),
        pytest.param(
            "vrrp 1 peer authentication ietf-md5 key-string <redacted>",
            id="vrrp-ietf-md5-key-string-already-redacted",
        ),
        pytest.param(
            "ip ospf authentication message-digest",
            id="ospf-auth-message-digest-untouched",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 version",
            id="snmp-host-version-without-value-untouched",
        ),
        pytest.param(
            "   description version 2c foo",
            id="description-version-2c-untouched",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 vrf MGMT udp-port 162",
            id="snmp-host-vrf-udp-port-no-community-untouched",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 version 3 noauth monUser",
            id="snmp-host-v3-noauth-user-untouched",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 informs version 3 auth monitorUser",
            id="snmp-host-informs-v3-auth-user-untouched",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1",
            id="snmp-host-no-community-untouched",
        ),
    ],
)
def test_mv1_8_23_24_eos_near_misses_are_byte_identical(text: str) -> None:
    """v3 user names, ``ietf-md5 key-string``, ``message-digest``, and
    ``version`` without a value must all stay byte-identical after redaction."""
    assert platform_redact.redact("eos", text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "vrrp 1 peer authentication text 7 <redacted:0a1b2c3d>",
            "vrrp 1 peer authentication text 7 <redacted:0a1b2c3d>",
            id="vrrp-placeholder-pin",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 version 2c <redacted:0a1b2c3d>",
            "snmp-server host 10.0.0.1 version 2c <redacted:0a1b2c3d>",
            id="snmp-host-placeholder-pin",
        ),
    ],
)
def test_mv1_8_23_24_eos_new_rules_preserve_placeholders(
    text: str, expected: str
) -> None:
    """existing placeholders in VRRP text and SNMP host values stay."""
    once = redact.redact_text(platform_redact.redact("eos", text))
    assert once == expected
    twice = redact.redact_text(platform_redact.redact("eos", once))
    assert twice == once


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "snmp-server host 10.0.0.1 NOVERCOMM",
            "snmp-server host 10.0.0.1 <redacted>",
            id="snmp-host-bare-redacts-community",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 traps NOVERTRAPS",
            "snmp-server host 10.0.0.1 traps <redacted>",
            id="snmp-host-traps-bare-redacts-community",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 vrf MGMT informs NOVERINF udp-port 162",
            "snmp-server host 10.0.0.1 vrf MGMT informs <redacted> udp-port 162",
            id="snmp-host-vrf-informs-bare-redacts-community",
        ),
        pytest.param(
            "SNMP-SERVER HOST 10.0.0.1 TRAPS UpComm1",
            "SNMP-SERVER HOST 10.0.0.1 TRAPS <redacted>",
            id="snmp-host-upper-case-traps-redacts-community",
        ),
        pytest.param(
            "snmp-server\thost\t10.0.0.1\ttraps\tTabComm9",
            "snmp-server\thost\t10.0.0.1\ttraps\t<redacted>",
            id="snmp-host-tab-separated-redacts-community",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 traps version 2c X1",
            "snmp-server host 10.0.0.1 traps version 2c <redacted>",
            id="snmp-host-traps-v2c-version-rule-unchanged",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 vrf MGMT version 1 X2",
            "snmp-server host 10.0.0.1 vrf MGMT version 1 <redacted>",
            id="snmp-host-vrf-v1-version-rule-unchanged",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 informs version 2c X3 udp-port 162",
            "snmp-server host 10.0.0.1 informs version 2c <redacted> udp-port 162",
            id="snmp-host-informs-v2c-version-rule-unchanged",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 version-leak",
            "snmp-server host 10.0.0.1 <redacted>",
            id="snmp-host-community-starting-version-redacted",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 traps-ro",
            "snmp-server host 10.0.0.1 <redacted>",
            id="snmp-host-community-starting-traps-redacted",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 informs-1",
            "snmp-server host 10.0.0.1 <redacted>",
            id="snmp-host-community-starting-informs-redacted",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 vrf MGMT informs vrf.leak udp-port 162",
            "snmp-server host 10.0.0.1 vrf MGMT informs <redacted> udp-port 162",
            id="snmp-host-community-starting-vrf-redacted",
        ),
        pytest.param(
            "snmp-server host 10.0.0.1 <redacted:0a1b2c3d>",
            "snmp-server host 10.0.0.1 <redacted:0a1b2c3d>",
            id="snmp-host-bare-placeholder-pin",
        ),
    ],
)
def test_mv1_8_25_eos_snmp_host_unversioned_redacts_community(
    text: str, expected: str
) -> None:
    """``snmp-server host ... <community>`` (no ``version`` keyword) redacts the
    community.  Existing v1/v2c lines still hit the version rule and redact exactly once."""
    once = redact.redact_text(platform_redact.redact("eos", text))
    assert once == expected
    # Idempotent on a second pass.
    twice = redact.redact_text(platform_redact.redact("eos", once))
    assert twice == once


# ---- Cisco IOS XE platform redaction ---------------------

IOSXE_FORMS = (
    # Rule 1: generic secret word + optional type + value
    pytest.param("enable secret 5 $1$IosSynth15a", ("IosSynth15a",), id="rule1-enable-secret-5"),
    pytest.param("enable secret 9 $9$IosSynth15b", ("IosSynth15b",), id="rule1-enable-secret-9"),
    pytest.param("enable secret 8 $8$IosSynth15c", ("IosSynth15c",), id="rule1-enable-secret-8"),
    pytest.param("enable secret 6 $6$IosSynth15d", ("IosSynth15d",), id="rule1-enable-secret-6"),
    pytest.param("enable secret IosSynth15e", ("IosSynth15e",), id="rule1-enable-secret-no-type"),
    pytest.param("enable password 0 IosSynth15f", ("IosSynth15f",), id="rule1-enable-password-0"),
    pytest.param("enable password 7 0822455D0A16AB", ("0822455D0A16AB",), id="rule1-enable-password-7"),
    pytest.param(
        "enable algorithm-type scrypt secret IosSynth15g",
        ("IosSynth15g",),
        id="rule1-enable-algo-scrypt-secret",
    ),
    pytest.param(
        "username u privilege 15 secret 9 IosSynth15h",
        ("IosSynth15h",),
        id="rule1-username-priv-secret-9",
    ),
    pytest.param(
        "username u password 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule1-username-password-7",
    ),
    pytest.param("key-string 7 0822455D", ("0822455D",), id="rule1-key-string-7"),
    pytest.param("key-string IosSynth15i", ("IosSynth15i",), id="rule1-key-string-no-type"),
    pytest.param(
        "ip ospf authentication-key 7 IosSynth15j",
        ("IosSynth15j",),
        id="rule1-ospf-auth-key-7",
    ),
    pytest.param(
        "ip ospf authentication-key 0 IosSynth15k",
        ("IosSynth15k",),
        id="rule1-ospf-auth-key-0",
    ),
    pytest.param(
        "ip ospf message-digest-key 1 md5 7 0822AB",
        ("0822AB",),
        id="rule1-ospf-message-digest-md5-7",
    ),
    pytest.param(
        "neighbor 192.0.2.1 password 7 0822AB",
        ("0822AB",),
        id="rule1-bgp-neighbor-password-7",
    ),
    pytest.param("ppp chap password 7 0822AB", ("0822AB",), id="rule1-ppp-chap-password-7"),
    pytest.param(
        "tacacs-server key 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule1-tacacs-server-key-7",
    ),
    pytest.param(
        "tacacs-server key IosSynth15l",
        ("IosSynth15l",),
        id="rule1-tacacs-server-key-no-type",
    ),
    pytest.param(
        "radius-server key 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule1-radius-server-key-7",
    ),
    pytest.param(
        "radius-server host 192.0.2.1 auth-port 1645 acct-port 1646 key 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule1-radius-host-key-7",
    ),
    pytest.param(
        "server-private 192.0.2.1 key 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule1-server-private-key-7",
    ),
    pytest.param(
        "radius server R\n key 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule1-radius-server-block-key-7",
    ),
    pytest.param(
        "tacacs server T\n key 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule1-tacacs-server-block-key-7",
    ),
    pytest.param(
        "ntp authentication-key 1 md5 IosSynth15m 7",
        ("IosSynth15m",),
        id="rule1-ntp-md5-X-7",
    ),
    pytest.param(
        "ntp authentication-key 1 md5 7 0822AB",
        ("0822AB",),
        id="rule1-ntp-md5-7-X",
    ),
    pytest.param("isis password IosSynth15n", ("IosSynth15n",), id="rule1-isis-password"),
    pytest.param("area-password IosSynth15o", ("IosSynth15o",), id="rule1-area-password"),
    pytest.param("domain-password IosSynth15p", ("IosSynth15p",), id="rule1-domain-password"),
    pytest.param(
        "crypto isakmp key 0 IosSynth15q address 192.0.2.1",
        ("IosSynth15q",),
        id="rule1-isakmp-key-0-address",
    ),
    pytest.param(
        "crypto isakmp key 6 IosSynth15r address 192.0.2.1",
        ("IosSynth15r",),
        id="rule1-isakmp-key-6-address",
    ),
    pytest.param(
        "crypto isakmp key IosSynth15s address 192.0.2.1",
        ("IosSynth15s",),
        id="rule1-isakmp-key-no-type",
    ),
    pytest.param("md5 key-string IosSynth15t", ("IosSynth15t",), id="rule1-md5-key-string-algkw"),
    pytest.param(
        "md5 key-string 7 IosSynth15u",
        ("IosSynth15u",),
        id="rule1-md5-key-string-algkw-type",
    ),
    # Rule 2: pre-shared-key and wpa-psk
    pytest.param(
        "pre-shared-key 0 IosSynth15v",
        ("IosSynth15v",),
        id="rule2-pre-shared-key-0",
    ),
    pytest.param(
        "pre-shared-key 6 IosSynth15w",
        ("IosSynth15w",),
        id="rule2-pre-shared-key-6",
    ),
    pytest.param(
        "pre-shared-key 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule2-pre-shared-key-7",
    ),
    pytest.param(
        "pre-shared-key local 0 IosSynth15x",
        ("IosSynth15x",),
        id="rule2-pre-shared-key-local-0",
    ),
    pytest.param(
        "pre-shared-key local IosSynth15y",
        ("IosSynth15y",),
        id="rule2-pre-shared-key-local",
    ),
    pytest.param(
        "pre-shared-key remote IosSynth15z",
        ("IosSynth15z",),
        id="rule2-pre-shared-key-remote",
    ),
    pytest.param(
        "wpa-psk ascii 0 IosSynth15aa",
        ("IosSynth15aa",),
        id="rule2-wpa-psk-ascii-0",
    ),
    pytest.param(
        "wpa-psk hex 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule2-wpa-psk-hex-7",
    ),
    pytest.param(
        "wpa-psk ascii IosSynth15ab",
        ("IosSynth15ab",),
        id="rule2-wpa-psk-ascii",
    ),
    # Rule 3: snmp-server community
    pytest.param(
        "snmp-server community IosSynth15ac RO",
        ("IosSynth15ac",),
        id="rule3-snmp-community-ro",
    ),
    pytest.param(
        "snmp-server community IosSynth15ad RW",
        ("IosSynth15ad",),
        id="rule3-snmp-community-rw",
    ),
    pytest.param(
        "snmp-server community IosSynth15ae view V RW acl 10",
        ("IosSynth15ae",),
        id="rule3-snmp-community-view-rw-acl",
    ),
    # Rule 4: snmp-server user line
    pytest.param(
        "snmp-server user U G v3 auth sha IosSynth15af priv aes 128 IosSynth15ag",
        ("IosSynth15af", "IosSynth15ag"),
        id="rule4-snmp-user-auth-priv-aes-128",
    ),
    pytest.param(
        "snmp-server user U G v3 auth md5 IosSynth15ah",
        ("IosSynth15ah",),
        id="rule4-snmp-user-auth-md5",
    ),
    pytest.param(
        "snmp-server user U G v3 priv des IosSynth15ai",
        ("IosSynth15ai",),
        id="rule4-snmp-user-priv-des",
    ),
    pytest.param(
        "snmp-server user U G v3 priv 3des IosSynth15aj",
        ("IosSynth15aj",),
        id="rule4-snmp-user-priv-3des",
    ),
    pytest.param(
        "snmp-server user U G v3 auth sha-2 256 IosSynth15ak",
        ("IosSynth15ak",),
        id="rule4-snmp-user-auth-sha-2-256",
    ),
    pytest.param(
        "snmp-server user U G v3 encrypted auth sha IosSynth15al",
        ("IosSynth15al",),
        id="rule4-snmp-user-encrypted",
    ),
    pytest.param(
        "snmp-server user U G v3 localized 0011LocIosSyn auth sha IosSynth15am priv aes IosSynth15an",
        ("IosSynth15am", "IosSynth15an"),
        id="rule4-snmp-user-localized",
    ),
    # Rule 5: snmp-server host
    pytest.param(
        "snmp-server host 192.0.2.5 IosSynth15ao",
        ("IosSynth15ao",),
        id="rule5-snmp-host-bare",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 traps IosSynth15ap",
        ("IosSynth15ap",),
        id="rule5-snmp-host-traps-bare",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 informs IosSynth15aq",
        ("IosSynth15aq",),
        id="rule5-snmp-host-informs-bare",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 vrf MGMT IosSynth15ar udp-port 162",
        ("IosSynth15ar",),
        id="rule5-snmp-host-vrf-bare",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 version 2c IosSynth15as",
        ("IosSynth15as",),
        id="rule5-snmp-host-version-2c",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 informs version 2c IosSynth15at udp-port 162",
        ("IosSynth15at",),
        id="rule5-snmp-host-informs-version-2c",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 version 1 IosSynth15au",
        ("IosSynth15au",),
        id="rule5-snmp-host-version-1",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 vrf MGMT version 1 IosSynth15av",
        ("IosSynth15av",),
        id="rule5-snmp-host-vrf-version-1",
    ),
    # Rule 6: HSRP / VRRP plain authentication
    pytest.param(
        "standby 1 authentication text IosSynth15aw",
        ("IosSynth15aw",),
        id="rule6-standby-text",
    ),
    pytest.param(
        "standby 1 authentication text 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule6-standby-text-7",
    ),
    pytest.param(
        "standby 1 authentication IosSynth15ax",
        ("IosSynth15ax",),
        id="rule6-standby-no-text",
    ),
    pytest.param(
        "vrrp 1 authentication text IosSynth15ay",
        ("IosSynth15ay",),
        id="rule6-vrrp-text",
    ),
    pytest.param(
        "vrrp 1 authentication text 7 0822455D0A16AB",
        ("0822455D0A16AB",),
        id="rule6-vrrp-text-7",
    ),
    pytest.param("enable password level 5 7 0822455D0A16A1", ("0822455D0A16A1",), id="lead-enable-password-level"),
    pytest.param("enable secret level 5 5 $1$abLeadQQ", ("$1$abLeadQQ", "abLeadQQ"), id="lead-enable-secret-level"),
    pytest.param("standby 1 authentication md5-LeadSynth1", ("md5-LeadSynth1",), id="lead-standby-md5-prefixed-value"),
    pytest.param(" ip nhrp authentication LeadSynt2", ("LeadSynt2",), id="lead-nhrp-authentication"),
    # Rule 7: GLBP plain authentication (next to the VRRP rule).
    pytest.param("glbp 1 authentication text GlbpSynth29a", ("GlbpSynth29a",), id="rule7-glbp-text"),
    pytest.param("glbp 1 authentication text 0 GlbpSynth29b", ("GlbpSynth29b",), id="rule7-glbp-text-0"),
    pytest.param("glbp 1 authentication text 7 GlbpSynth29c", ("GlbpSynth29c",), id="rule7-glbp-text-7"),
    pytest.param("glbp 10 authentication md5 key-string 7 GlbpSynth29d", ("GlbpSynth29d",), id="rule7-glbp-md5-key-string"),
    # Rule 7: OSPFv3 / IPv6 OSPF IPsec (line-scoped to whole-word ``ipsec`` then ``spi``).
    pytest.param("ipv6 ospf authentication ipsec spi 500 sha1 IpsecSynth29b", ("IpsecSynth29b",), id="rule7-ipv6-ospf-sha1"),
    pytest.param(
        "ospfv3 1 encryption ipsec spi 256 esp aes-cbc 128 EspSynth29c sha1 EspSynth29d",
        ("EspSynth29c", "EspSynth29d"),
        id="rule7-ospfv3-aes-cbc-128",
    ),
    pytest.param("area 0 authentication ipsec spi 256 sha1 0 IpsecSynth29e", ("IpsecSynth29e",), id="rule7-area-ipsec-sha1"),
    pytest.param(
        "ipv6 ospf encryption ipsec spi 300 esp 3des 7 EspSynth29f md5 7 EspSynth29g",
        ("EspSynth29f", "EspSynth29g"),
        id="rule7-ipv6-ospf-3des-md5",
    ),
    pytest.param(
        "ospfv3 encryption ipsec spi 301 esp des EspSynth29h sha1 EspSynth29i",
        ("EspSynth29h", "EspSynth29i"),
        id="rule7-ospfv3-des",
    ),
    pytest.param(
        "ospfv3 encryption ipsec spi 302 esp null sha1 EspSynth29j",
        ("EspSynth29j",),
        id="rule7-ospfv3-null",
    ),
    pytest.param(
        "ospfv3 encryption ipsec spi 303 esp aes-cbc 256 EspSynth29k sha1 EspSynth29l",
        ("EspSynth29k", "EspSynth29l"),
        id="rule7-ospfv3-aes-cbc-256",
    ),
    # Rule 7: Catalyst 9800 WLAN PSK set-key (``-`` before ``key`` blocks rule 1's lookbehind).
    pytest.param("security wpa psk set-key ascii 0 WlanSynth29k", ("WlanSynth29k",), id="rule7-set-key-ascii-0"),
    pytest.param("security wpa psk set-key hex 8 WlanSynth29l", ("WlanSynth29l",), id="rule7-set-key-hex-8"),
    pytest.param("security wpa psk set-key ascii WlanSynth29m", ("WlanSynth29m",), id="rule7-set-key-ascii"),
    # Rule 7: Cisco TrustSec ``cts manual`` ``sap pmk <hex-key> [mode-list <modes...>]``;
    # the lookbehind keeps ``sapx pmk`` / ``sap pmkfoo`` byte-identical.
    pytest.param(
        "sap pmk 0123ABCDCtsSynth35i mode-list gcm-encrypt gmac",
        ("0123ABCDCtsSynth35i",),
        id="rule7-cts-sap-pmk-mode-list",
    ),
    pytest.param(
        "sap pmk 0123ABCDCtsSynth35j",
        ("0123ABCDCtsSynth35j",),
        id="rule7-cts-sap-pmk-no-mode-list",
    ),
    pytest.param(
        " SAP PMK 0123ABCDCtsSynth35k mode-list null",
        ("0123ABCDCtsSynth35k",),
        id="rule7-cts-sap-pmk-case-mode-list",
    ),
)


@pytest.mark.parametrize(("text", "secrets"), IOSXE_FORMS)
def test_mv1_9_15_iosxe_forms_redact_synthetic_secrets(
    text: str, secrets: tuple[str, ...]
) -> None:
    """Every IOS XE form named in rules 1-6 redacts its synthetic secret."""
    direct = platform_redact.redact("iosxe", text)
    combined = redact.redact_text(direct)
    for value in secrets:
        assert value not in direct, f"direct leak: {value!r} in {direct!r}"
        assert value not in combined, f"shared leak: {value!r} in {combined!r}"
    # The label words and type tokens remain.
    keep_tokens = (
        "enable", "secret", "password", "type", "algorithm-type", "scrypt",
        "username", "privilege", "key-string", "ip", "ospf",
        "authentication-key", "message-digest-key", "md5", "neighbor",
        "ppp", "chap", "tacacs-server", "radius-server", "auth-port",
        "acct-port", "host", "key", "server-private", "radius", "server",
        "ntp", "authentication-key", "isis", "area-password",
        "domain-password", "crypto", "isakmp", "address", "pre-shared-key",
        "local", "remote", "wpa-psk", "ascii", "hex", "snmp-server",
        "community", "RO", "RW", "view", "acl", "user", "auth", "priv",
        "aes", "md5", "sha", "sha-2", "des", "3des", "128", "192", "256",
        "encrypted", "localized", "v3", "traps", "informs", "vrf", "MGMT",
        "udp-port", "version", "2c", "standby", "authentication",
        "text", "vrrp", "glbp", "ospfv3", "ipv6", "ospf", "area",
        "encryption", "ipsec", "spi", "10", "300", "301", "302",
        "303", "500", "esp", "aes-cbc", "null", "set-key", "security",
        "wpa", "psk", "sha1", "0", "5", "6", "7", "8", "9",
        "sap", "pmk", "mode-list", "gcm-encrypt", "gmac",
        "SAP", "PMK",
    )
    for token in keep_tokens:
        if token in text.split():
            assert token in direct, f"lost label/type token: {token!r}"


IOSXE_FORMS_CASE = (
    pytest.param(
        "ENABLE SECRET 9 $9$UpSynth16a",
        ("UpSynth16a",),
        id="upper-case-enable-secret-9",
    ),
    pytest.param(
        "Snmp-Server Community UpSynth16b RO",
        ("UpSynth16b",),
        id="mixed-case-snmp-community",
    ),
    pytest.param(
        "Key-String 7 UpSynth16c",
        ("UpSynth16c",),
        id="mixed-case-key-string-7",
    ),
    pytest.param(
        "SNMP-SERVER USER U G V3 AUTH SHA UpSynth16d PRIV AES 128 UpSynth16e",
        ("UpSynth16d", "UpSynth16e"),
        id="upper-case-snmp-user",
    ),
    pytest.param(
        "Snmp-Server Host 192.0.2.5 VERSION 2C UpSynth16f",
        ("UpSynth16f",),
        id="mixed-case-snmp-host-version-2c",
    ),
    pytest.param(
        "Crypto Isakmp Key 0 UpSynth16g Address 192.0.2.1",
        ("UpSynth16g",),
        id="mixed-case-isakmp-key",
    ),
    pytest.param(
        "Pre-Shared-Key Local 0 UpSynth16h",
        ("UpSynth16h",),
        id="mixed-case-pre-shared-key-local",
    ),
    pytest.param(
        "Standby 1 Authentication Text UpSynth16i",
        ("UpSynth16i",),
        id="mixed-case-standby-text",
    ),
    pytest.param(
        "Glbp 10 Authentication Text 0 UpSynth16j",
        ("UpSynth16j",),
        id="mixed-case-glbp-text-0",
    ),
    # case-insensitive coverage for the ipsec and set-key rules
    # that dropped every byte case check in an earlier version.  Each line varies the
    # casing of a different keyword so removing IGNORECASE (or ``(?mi)`` -> ``(?m)``
    # on the ipsec line rule) turns at least one of these red.
    pytest.param(
        "IPV6 OSPF AUTHENTICATION IPSEC SPI 500 SHA1 IpsecUpper35a",
        ("IpsecUpper35a",),
        id="upper-case-ipv6-ospf-ipsec-line-word-hash",
    ),
    pytest.param(
        "ipv6 ospf authentication IPSEC spi 500 sha1 IpsecUpper35b",
        ("IpsecUpper35b",),
        id="upper-case-ipv6-ospf-ipsec-word-only",
    ),
    pytest.param(
        "ipv6 ospf authentication ipsec SPI 500 sha1 IpsecUpper35c",
        ("IpsecUpper35c",),
        id="upper-case-ipv6-ospf-ipsec-spi-only",
    ),
    pytest.param(
        "ospfv3 1 encryption ipsec spi 256 ESP AES-CBC 128 EspUpper35d sha1 EspUpper35e",
        ("EspUpper35d", "EspUpper35e"),
        id="upper-case-ospfv3-esp-aes-cbc",
    ),
    pytest.param(
        "ipv6 ospf authentication ipsec spi 501 MD5 7 IpsecUpper35f",
        ("IpsecUpper35f",),
        id="upper-case-ipv6-ospf-ipsec-md5",
    ),
    pytest.param(
        "SECURITY WPA PSK SET-KEY ASCII 0 WlanUpper35g",
        ("WlanUpper35g",),
        id="upper-case-security-wpa-psk-set-key",
    ),
    pytest.param(
        "security wpa psk Set-Key Hex 8 WlanUpper35h",
        ("WlanUpper35h",),
        id="mixed-case-security-wpa-psk-set-key",
    ),
    # mixed-case ``cts manual`` sap pmk coverage.
    pytest.param(
        "Sap Pmk 0123ABCDEFCtsUpper35i Mode-List Gcm-Encrypt Gmac",
        ("0123ABCDEFCtsUpper35i",),
        id="mixed-case-cts-sap-pmk-mode-list",
    ),
)


@pytest.mark.parametrize(("text", "secrets"), IOSXE_FORMS_CASE)
def test_mv1_9_16_iosxe_case_insensitive_rules_redact_secrets(
    text: str, secrets: tuple[str, ...]
) -> None:
    """Every IOS XE rule redacts in any case; case is not a leak."""
    direct = platform_redact.redact("iosxe", text)
    for value in secrets:
        assert value not in direct, f"case-insensitive leak: {value!r} in {direct!r}"


IOSXE_FORMS_WHOLE_WORD = (
    pytest.param(
        "secret 7abcSynth",
        ("7abcSynth",),
        id="value-starts-with-type-token-digit",
    ),
    pytest.param(
        "key chainSynth",
        ("chainSynth",),
        id="value-starts-with-chain-not-whole-word",
    ),
    pytest.param(
        "pre-shared-key localSynth",
        ("localSynth",),
        id="pre-shared-key-value-starts-with-local",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 version-leak",
        ("version-leak",),
        id="snmp-host-community-version-prefix-redacted",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 traps-ro",
        ("traps-ro",),
        id="snmp-host-community-traps-prefix-redacted",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 informs-1 udp-port 162",
        ("informs-1",),
        id="snmp-host-community-informs-prefix-redacted",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 vrf.leak",
        ("vrf.leak",),
        id="snmp-host-community-vrf-prefix-redacted",
    ),
    pytest.param(
        "snmp-server user u g v3 priv aes 128x PrivSynth",
        ("PrivSynth", "128x"),
        id="snmp-user-priv-128x-trailing-token-redacted",
    ),
    pytest.param(
        "snmp-server user u g v3 auth sha 128x AuthSynth29n",
        ("AuthSynth29n", "128x"),
        id="snmp-user-auth-128x-trailing-token-redacted",
    ),
)


@pytest.mark.parametrize(("text", "secrets"), IOSXE_FORMS_WHOLE_WORD)
def test_mv1_9_17_iosxe_whole_word_keywords_redact_values(
    text: str, secrets: tuple[str, ...]
) -> None:
    """Whole-word keywords ``version|vrf|traps|informs|udp-port`` and ``local|remote``
    only count as keywords when followed by whitespace; a value that starts with
    the keyword is still redacted, and ``priv aes 128x PrivSynth`` does not leak."""
    direct = platform_redact.redact("iosxe", text)
    for value in secrets:
        assert value not in direct, f"whole-word leak: {value!r} in {direct!r}"


IOSXE_NEAR_MISSES = (
    pytest.param("key chain KC", id="near-miss-key-chain"),
    pytest.param("service password-encryption", id="near-miss-service-password-encryption"),
    pytest.param(
        "ip rip authentication key-chain KC",
        id="near-miss-rip-key-chain-token",
    ),
    pytest.param(
        "snmp-server host 192.0.2.5 version 3 priv NewtonV3User",
        id="near-miss-snmp-host-v3-user-name",
    ),
    pytest.param(
        "snmp-server user NewtonV3User G v3",
        id="near-miss-snmp-user-no-auth",
    ),
    pytest.param(
        "description version 2c foo",
        id="near-miss-description-version-2c",
    ),
    pytest.param(
        "interface GigabitEthernet1",
        id="near-miss-interface-line",
    ),
    pytest.param(
        "ip ssh pubkey-chain",
        id="near-miss-pubkey-chain",
    ),
    pytest.param(
        "key-hash ssh-rsa AAAAsynthetic",
        id="near-miss-key-hash",
    ),
    # ``sha1`` / ``md5`` outside an ``ipsec ... spi ...`` line
    # stays byte-identical.  These pin the new ipsec line scoping so a future
    # widening of the line scope (or a stray sha1|md5 anywhere) turns red.
    pytest.param(
        "crypto isakmp policy 10",
        id="near-miss-crypto-isakmp-policy",
    ),
    pytest.param(
        "crypto isakmp policy 10 hash sha1",
        id="near-miss-crypto-isakmp-policy-hash-sha1",
    ),
    pytest.param(
        "crypto isakmp policy 10 authentication sha1 SomeName",
        id="near-miss-crypto-isakmp-policy-auth-sha1",
    ),
    pytest.param(
        "hash sha1",
        id="near-miss-bare-hash-sha1",
    ),
    pytest.param(
        "authentication sha1 SomeName",
        id="near-miss-bare-authentication-sha1",
    ),
    pytest.param(
        "description spi 5 sha1 SomeName",
        id="near-miss-spi-without-ipsec",
    ),
    # standby ``(?!md5...)`` exclusion pin.  ``md5`` as a
    # bare keyword (no following secret value) stays.
    pytest.param(
        "standby 1 authentication md5",
        id="near-miss-standby-md5-no-value",
    ),
    # ``sap pmk`` whole-word guards.  ``sap`` must be a
    # whole word (not preceded by ``-``/``_``/alnum) and ``pmk`` must
    # follow ``sap`` with whitespace, not be glued to another word.
    pytest.param(
        "description sap pmkfoo bar",
        id="near-miss-sap-pmkfoo-glued",
    ),
    pytest.param(
        "sapx pmk Foo",
        id="near-miss-sapx-pmk-not-whole-word-sap",
    ),
    # The lookbehind on ``sap`` blocks a left-side glued word.
    pytest.param(
        "xsap pmk FooLeftGuard",
        id="near-miss-sap-left-glued",
    ),
    pytest.param(
        "sap-pmk FooLeftGuard",
        id="near-miss-sap-hyphen-pmk-not-whole",
    ),
)


@pytest.mark.parametrize("text", IOSXE_NEAR_MISSES)
def test_mv1_9_18_iosxe_near_misses_are_byte_identical(text: str) -> None:
    """IOS XE neighbours that share tokens with the secret rules stay."""
    assert platform_redact.redact("iosxe", text) == text


@pytest.mark.parametrize(
    "fixture_path",
    [
        pytest.param(p, id=p.name)
        for p in sorted((FIXTURES_DIR / "iosxe").iterdir())
        if p.is_file() and "error" not in p.name
    ],
)
def test_mv1_9_18_iosxe_enabled_getter_fixtures_byte_identical(
    fixture_path: Path,
) -> None:
    """Shipped IOS XE non-error fixtures are byte-identical after redaction."""
    text = fixture_path.read_text(encoding="utf-8")
    assert platform_redact.redact("iosxe", text) == text


def test_mv1_9_19_iosxe_idempotence_and_placeholders() -> None:
    """Every IOS XE rule is idempotent and keeps existing placeholders."""
    text = (
        "enable secret 9 $9$IdemSynth19a\n"
        "enable password 0 IdemSynth19b\n"
        "username u privilege 15 secret 9 IdemSynth19c\n"
        "username u password 7 0822455D0A16AB\n"
        "key-string 7 0822455D\n"
        "ip ospf authentication-key 7 IdemSynth19d\n"
        "ip ospf message-digest-key 1 md5 7 0822AB\n"
        "neighbor 192.0.2.1 password 7 0822AB\n"
        "ppp chap password 7 0822AB\n"
        "tacacs-server key 7 0822455D0A16AB\n"
        "radius-server host 192.0.2.1 auth-port 1645 acct-port 1646 key 7 0822455D0A16AB\n"
        "server-private 192.0.2.1 key 7 0822455D0A16AB\n"
        "ntp authentication-key 1 md5 IdemSynth19e 7\n"
        "isis password IdemSynth19f\n"
        "area-password IdemSynth19g\n"
        "domain-password IdemSynth19h\n"
        "crypto isakmp key 0 IdemSynth19i address 192.0.2.1\n"
        "pre-shared-key local 0 IdemSynth19j\n"
        "wpa-psk ascii 0 IdemSynth19k\n"
        "snmp-server community IdemSynth19l RO\n"
        "snmp-server user U G v3 auth sha IdemSynth19m priv aes 128 IdemSynth19n\n"
        "snmp-server host 192.0.2.5 version 2c IdemSynth19o\n"
        "snmp-server host 192.0.2.5 IdemSynth19p\n"
        "standby 1 authentication text IdemSynth19q\n"
        "vrrp 1 authentication text IdemSynth19r\n"
        "secret 7 <redacted:0a1b2c3d>\n"
        "snmp-server community <redacted:0a1b2c3d> ro\n"
        "standby 1 authentication text <redacted>\n"
        # GLBP, OSPFv3 IPsec and Catalyst set-key forms
        # also have to be idempotent and keep the existing placeholders.
        "glbp 1 authentication text IdemSynth29a\n"
        "glbp 2 authentication text 7 IdemSynth29b\n"
        "ipv6 ospf authentication ipsec spi 500 sha1 IdemSynth29c\n"
        "ospfv3 1 encryption ipsec spi 256 esp aes-cbc 128 IdemSynth29d sha1 IdemSynth29e\n"
        "security wpa psk set-key ascii 0 IdemSynth29f\n"
        "security wpa psk set-key hex 8 IdemSynth29g\n"
        "glbp 1 authentication text <redacted>\n"
        "ipv6 ospf authentication ipsec spi 500 sha1 <redacted:0a1b2c3d>\n"
        "security wpa psk set-key ascii 0 <redacted>\n"
        # cts sap pmk idempotence / placeholder.
        "sap pmk 0123ABCDCtsSynth19s mode-list gcm-encrypt gmac\n"
        "sap pmk <redacted:0a1b2c3d> mode-list gcm-encrypt gmac\n"
    )
    once = platform_redact.redact("iosxe", text)
    twice = platform_redact.redact("iosxe", once)
    assert twice == once, "iosxe platform redaction is not idempotent"
    for fragment in (
        "IdemSynth19a", "IdemSynth19b", "IdemSynth19c", "0822455D0A16AB",
        "0822455D", "IdemSynth19d", "0822AB", "IdemSynth19e", "IdemSynth19f",
        "IdemSynth19g", "IdemSynth19h", "IdemSynth19i", "IdemSynth19j",
        "IdemSynth19k", "IdemSynth19l", "IdemSynth19m", "IdemSynth19n",
        "IdemSynth19o", "IdemSynth19p", "IdemSynth19q", "IdemSynth19r",
        "IdemSynth29a", "IdemSynth29b", "IdemSynth29c",
        "IdemSynth29d", "IdemSynth29e", "IdemSynth29f", "IdemSynth29g",
        "0123ABCDCtsSynth19s",
    ):
        assert fragment not in once, f"leaked secret: {fragment!r}"
    # Pin the placeholder lines byte-identical.
    assert "secret 7 <redacted:0a1b2c3d>" in once
    assert "snmp-server community <redacted:0a1b2c3d> ro" in once
    assert "standby 1 authentication text <redacted>" in once
    assert "glbp 1 authentication text <redacted>" in once
    assert "ipv6 ospf authentication ipsec spi 500 sha1 <redacted:0a1b2c3d>" in once
    assert "security wpa psk set-key ascii 0 <redacted>" in once
    # cts sap pmk idempotence + placeholder survives.
    assert "sap pmk <redacted> mode-list gcm-encrypt gmac" in once
    assert "sap pmk <redacted:0a1b2c3d> mode-list gcm-encrypt gmac" in once


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("secret 7 " * 25_000, id="iosxe-secret-7-no-value"),
        pytest.param(
            "snmp-server host 192.0.2.5 vrf " * 15_000,
            id="iosxe-snmp-host-vrf-no-value",
        ),
        pytest.param(
            "pre-shared-key local " * 16_000,
            id="iosxe-pre-shared-key-local-no-value",
        ),
        pytest.param(
            "ipsec spi 1 esp aes-cbc 128 " * 10_000,
            id="iosxe-ipsec-esp-200kb",
        ),
        pytest.param("ipsec " * 4_000, id="iosxe-ipsec-no-spi-one-line"),
        pytest.param("ipsec spi " * 20_000, id="iosxe-ipsec-spi-pairs-one-line"),
        pytest.param(
            "snmp-server user u g v3 auth sha " + ("a " * 50_000),
            id="iosxe-auth-greedy-200kb",
        ),
        # regression pin for the r4 auth-greedy regex.
        # 65 KB is large enough to fail the 1 s bound on HEAD (~37 s on
        # the auth case, ~40 s on priv) while keeping the red run quick.
        pytest.param(
            "snmp-server user auth " + ("x" * 65_000),
            id="iosxe-auth-greedy-65kb",
        ),
        pytest.param(
            "snmp-server user priv " + ("x" * 65_000),
            id="iosxe-priv-greedy-65kb",
        ),
        # The 200 KB case keeps a realistic worst-case bound on the fixed
        # regex; without it a small-replacement fix (e.g. capping the
        # quantifier) that leaks only on big inputs would not be caught.
        pytest.param(
            "snmp-server user auth " + ("x" * 200_000),
            id="iosxe-auth-greedy-200kb-no-value",
        ),
        pytest.param(
            "snmp-server user priv " + ("x" * 200_000),
            id="iosxe-priv-greedy-200kb-no-value",
        ),
        pytest.param(
            ("sap pmk " + "X" * 200_000),
            id="iosxe-cts-sap-pmk-200kb-no-mode-list",
        ),
    ],
)
def test_mv1_9_20_iosxe_rules_are_linear_time(text: str) -> None:
    """Each IOS XE rule stays linear on 200 KB of stress input."""
    start = time.perf_counter()
    platform_redact.redact("iosxe", text)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"redact took {elapsed:.3f}s"


@pytest.mark.parametrize(
    ("platform", "text", "expected"),
    [
        pytest.param(
            "eos",
            "crypto isakmp key 0 IkeSynth address 192.0.2.1",
            "crypto isakmp key 0 <redacted> address 192.0.2.1",
            id="isolation-eos-isakmp",
        ),
        pytest.param(
            "eos",
            "domain-password DomSynth",
            "domain-password DomSynth",
            id="isolation-eos-domain-password",
        ),
        pytest.param(
            "junos",
            "crypto isakmp key 0 IkeSynth address 192.0.2.1",
            "crypto isakmp key 0 IkeSynth address 192.0.2.1",
            id="isolation-junos-isakmp",
        ),
        pytest.param(
            "junos",
            "domain-password DomSynth",
            "domain-password DomSynth",
            id="isolation-junos-domain-password",
        ),
        pytest.param(
            "vyos",
            "crypto isakmp key 0 IkeSynth address 192.0.2.1",
            "crypto isakmp key <redacted> IkeSynth address 192.0.2.1",
            id="isolation-vyos-isakmp",
        ),
        pytest.param(
            "vyos",
            "domain-password DomSynth",
            "domain-password DomSynth",
            id="isolation-vyos-domain-password",
        ),
        pytest.param(
            "routeros",
            "crypto isakmp key 0 IkeSynth address 192.0.2.1",
            "crypto isakmp key 0 IkeSynth address 192.0.2.1",
            id="isolation-routeros-isakmp",
        ),
        pytest.param(
            "routeros",
            "domain-password DomSynth",
            "domain-password DomSynth",
            id="isolation-routeros-domain-password",
        ),
        pytest.param(
            "openwrt",
            "crypto isakmp key 0 IkeSynth address 192.0.2.1",
            "crypto isakmp key 0 IkeSynth address 192.0.2.1",
            id="isolation-openwrt-isakmp",
        ),
        pytest.param(
            "openwrt",
            "domain-password DomSynth",
            "domain-password DomSynth",
            id="isolation-openwrt-domain-password",
        ),
    ],
)
def test_mv1_9_21_iosxe_does_not_change_other_platforms(
    platform: str, text: str, expected: str
) -> None:
    """The iosxe branch must leave the other platforms byte-identical."""
    assert platform_redact.redact(platform, text) == expected


# ---- Fortinet FortiOS platform redaction ---------------------

FORTIOS_FORMS = (
    # Rule 1: ENC anywhere (whole-word ENC + whitespace + bare or quoted value).
    pytest.param(
        "set password ENC QUJDREVGRw==",
        ("QUJDREVGRw==",),
        id="rule1-password-enc-bare",
    ),
    pytest.param(
        'set password ENC "QUJDREVGRw=="',
        ("QUJDREVGRw==",),
        id="rule1-password-enc-quoted",
    ),
    pytest.param(
        "set secret ENC QUJDRGFnU3ludGgyM2I=",
        ("QUJDRGFnU3ludGgyM2I=",),
        id="rule1-secret-enc-bare",
    ),
    pytest.param(
        "set ha-mgmt-secret ENC QUJDREVGRw==",
        ("QUJDREVGRw==",),
        id="rule1-ha-mgmt-secret-enc-not-in-rule2",
    ),
    pytest.param(
        "set some-token ENC QUJDREVGRw==",
        ("QUJDREVGRw==",),
        id="rule1-some-token-enc-not-in-rule2",
    ),
    pytest.param(
        "set ENC QUJDREVGRw==",
        ("QUJDREVGRw==",),
        id="rule1-enc-no-preceding-secret-word",
    ),
    # Rule 2: set <secretword> [ENC] <value> -- each secret word gets its own
    # distinct synthetic secret (bare, quoted, or unclosed).
    pytest.param(
        "set password FgSynth23a",
        ("FgSynth23a",),
        id="rule2-password-bare",
    ),
    pytest.param(
        'set password "FgSynth23b"',
        ("FgSynth23b",),
        id="rule2-password-quoted",
    ),
    pytest.param(
        'set password "FgSynth23c',
        ("FgSynth23c",),
        id="rule2-password-unclosed-quoted-to-eof",
    ),
    pytest.param(
        "set passwd FgSynth23d",
        ("FgSynth23d",),
        id="rule2-passwd",
    ),
    pytest.param(
        "set psksecret ENC QUJDRGFnU3ludGgyM2I=",
        ("QUJDRGFnU3ludGgyM2I=",),
        id="rule2-psksecret-enc",
    ),
    pytest.param(
        'set psksecret "FgSynth23e"',
        ("FgSynth23e",),
        id="rule2-psksecret-quoted",
    ),
    pytest.param(
        "set psksecret-remote FgSynth23f",
        ("FgSynth23f",),
        id="rule2-psksecret-remote",
    ),
    pytest.param(
        "set ppk-secret FgSynth23g",
        ("FgSynth23g",),
        id="rule2-ppk-secret",
    ),
    pytest.param(
        "set secret FgSynth23h",
        ("FgSynth23h",),
        id="rule2-secret",
    ),
    pytest.param(
        "set key ENC QUJDREVGRw==",
        ("QUJDREVGRw==",),
        id="rule2-key-enc",
    ),
    pytest.param(
        "set key-string ENC QUJDREVGRw==",
        ("QUJDREVGRw==",),
        id="rule2-key-string-enc",
    ),
    pytest.param(
        'set md5-key "FgSynth23i"',
        ("FgSynth23i",),
        id="rule2-md5-key-quoted",
    ),
    pytest.param(
        "set auth-pwd ENC QUJDRGFnU3ludGgyM2I=",
        ("QUJDRGFnU3ludGgyM2I=",),
        id="rule2-auth-pwd-enc",
    ),
    pytest.param(
        "set priv-pwd ENC QUJDREVGRw==",
        ("QUJDREVGRw==",),
        id="rule2-priv-pwd-enc",
    ),
    pytest.param(
        "set auth-password FgSynth23j",
        ("FgSynth23j",),
        id="rule2-auth-password",
    ),
    pytest.param(
        "set passphrase FgSynth23k",
        ("FgSynth23k",),
        id="rule2-passphrase",
    ),
    pytest.param(
        'set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
        'MIIBHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwGgQU0N2t3vUg\n'
        '-----END ENCRYPTED PRIVATE KEY-----"',
        (
            "MIIBHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwGgQU0N2t3vUg",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----END ENCRYPTED PRIVATE KEY-----",
        ),
        id="rule2-private-key-multi-line",
    ),
    pytest.param(
        "set pre-shared-key FgSynth23m",
        ("FgSynth23m",),
        id="rule2-pre-shared-key",
    ),
    pytest.param(
        "set sso-password FgSynth23n",
        ("FgSynth23n",),
        id="rule2-sso-password",
    ),
    pytest.param(
        "set ldap-password FgSynth23o",
        ("FgSynth23o",),
        id="rule2-ldap-password",
    ),
    # Rule 3: SNMP community blocks.  The full nested block is one of the
    # forms the contract names.
    pytest.param(
        'config system snmp community\n'
        '    edit 1\n'
        '        set name "FgComm23"\n'
        '    next\n'
        'end',
        ("FgComm23",),
        id="rule3-snmp-community-set-name-quoted",
    ),
    pytest.param(
        'config system snmp community\n'
        '    edit 1\n'
        '        set name FgComm24\n'
        '    next\n'
        'end',
        ("FgComm24",),
        id="rule3-snmp-community-set-name-bare",
    ),
    pytest.param(
        'config system snmp community\n'
        '    edit 1\n'
        '        set name "FgComm25"\n'
        '        config hosts\n'
        '            edit 1\n'
        '                set ip 192.0.2.9 255.255.255.255\n'
        '            next\n'
        '        end\n'
        '    next\n'
        'end',
        ("FgComm25",),
        id="rule3-snmp-community-full-nested-block",
    ),
    # set name AFTER the nested end -- this is the case that catches a depth
    # counter replaced by "ends at the first `end`".
    pytest.param(
        'config system snmp community\n'
        '    edit 1\n'
        '        config hosts\n'
        '            edit 1\n'
        '                set ip 192.0.2.9 255.255.255.255\n'
        '            next\n'
        '        end\n'
        '        set name "FgComm26"\n'
        '    next\n'
        'end',
        ("FgComm26",),
        id="rule3-snmp-community-set-name-after-nested-end",
    ),
    pytest.param('set md5-keys 1 "FgLeadMd5a"', ("FgLeadMd5a",), id="lead-md5-keys-with-id"),
    pytest.param("set md5-key 2 FgLeadMd5b", ("FgLeadMd5b",), id="lead-md5-key-with-id"),
)


@pytest.mark.parametrize(("text", "secrets"), FORTIOS_FORMS)
def test_mv1_9_23_fortios_forms_redact_synthetic_secrets(
    text: str, secrets: tuple[str, ...]
) -> None:
    """Every FortiOS form named in rules 1-3 redacts its synthetic secret."""
    direct = platform_redact.redact("fortios", text)
    combined = redact.redact_text(direct)
    for value in secrets:
        assert value not in direct, f"direct leak: {value!r} in {direct!r}"
        assert value not in combined, f"shared leak: {value!r} in {combined!r}"
    keep_tokens = (
        "set", "password", "passwd", "psksecret", "psksecret-remote",
        "ppk-secret", "secret", "key", "key-string", "md5-key",
        "auth-pwd", "priv-pwd", "auth-password", "passphrase",
        "private-key", "pre-shared-key", "sso-password", "ldap-password",
        "ENC", "config", "system", "snmp", "community", "edit",
        "next", "end",
    )
    for token in keep_tokens:
        if token in text.split():
            assert token in direct, f"lost label/type token: {token!r}"


FORTIOS_CASE_FORMS = (
    pytest.param(
        "SET PASSWORD ENC QUJDREVGRw==",
        ("QUJDREVGRw==",),
        id="uppercase-password-enc",
    ),
    pytest.param(
        "Set Psksecret enc QUJDREVGRw==",
        ("QUJDREVGRw==",),
        id="mixed-case-psksecret-enc",
    ),
    pytest.param(
        'CONFIG SYSTEM SNMP COMMUNITY\n'
        '    EDIT 1\n'
        '        SET NAME "UpComm24c"\n'
        '    NEXT\n'
        'END',
        ("UpComm24c",),
        id="uppercase-snmp-community-block",
    ),
    pytest.param(
        "set password ENCsynthX",
        ("ENCsynthX",),
        id="value-starts-with-ENC-not-the-keyword",
    ),
    pytest.param(
        "set psksecret ENC-ish",
        ("ENC-ish",),
        id="value-ENC-ish-not-the-ENC-keyword",
    ),
    pytest.param(
        "SET password FgCase24f",
        ("FgCase24f",),
        id="uppercase-set-keyword-no-ENC",
    ),
    pytest.param(
        "Set PASSWORD FgCase24g",
        ("FgCase24g",),
        id="mixed-case-set-and-secret-word",
    ),
    pytest.param(
        "set some-token enc QUJDRmdDYXNlMjlv",
        ("QUJDRmdDYXNlMjlv",),
        id="lower-case-enc-not-secret-word",
    ),
    pytest.param(
        "set ha-mgmt-secret Enc QUJDRmdDYXNlMjlw",
        ("QUJDRmdDYXNlMjlw",),
        id="mixed-case-enc-not-secret-word",
    ),
)


@pytest.mark.parametrize(("text", "secrets"), FORTIOS_CASE_FORMS)
def test_mv1_9_24_fortios_case_and_whole_word_rules_redact_secrets(
    text: str, secrets: tuple[str, ...]
) -> None:
    """Every FortiOS rule redacts in any case; ``ENC`` only counts when
    followed by whitespace, and a value that starts with ``ENC`` is still redacted."""
    direct = platform_redact.redact("fortios", text)
    for value in secrets:
        assert value not in direct, f"case/whole-word leak: {value!r} in {direct!r}"


FORTIOS_NEAR_MISSES = (
    pytest.param("set name \"port1\"", id="near-miss-name-bare-no-block"),
    pytest.param(
        'config system interface\n    edit "port1"\n        set name "wan"\n    next\nend',
        id="near-miss-set-name-in-interface-block",
    ),
    pytest.param(
        'config firewall policy\n    edit 1\n        set name "allow-web"\n    next\nend',
        id="near-miss-set-name-in-firewall-policy-block",
    ),
    pytest.param("set passwordx foo", id="near-miss-passwordx-not-whole-word"),
    pytest.param(
        "set password-policy enable", id="near-miss-password-policy-not-whole-word"
    ),
    pytest.param(
        "set enc-algorithm aes256", id="near-miss-enc-algorithm-not-the-ENC-keyword"
    ),
    pytest.param("set status enable", id="near-miss-status-not-a-secret-word"),
)


@pytest.mark.parametrize("text", FORTIOS_NEAR_MISSES)
def test_mv1_9_25_fortios_near_misses_are_byte_identical(text: str) -> None:
    """FortiOS neighbours that share tokens with the secret rules stay."""
    assert platform_redact.redact("fortios", text) == text


@pytest.mark.parametrize(
    "fixture_path",
    [
        pytest.param(p, id=p.name)
        for p in sorted((FIXTURES_DIR / "fortios").iterdir())
        if p.is_file() and "error" not in p.name
    ],
)
def test_mv1_9_25_fortios_enabled_getter_fixtures_byte_identical(
    fixture_path: Path,
) -> None:
    """Shipped FortiOS non-error fixtures are byte-identical after redaction."""
    text = fixture_path.read_text(encoding="utf-8")
    assert platform_redact.redact("fortios", text) == text


def test_mv1_9_25_fortios_snmp_community_close_leaves_following_set_name() -> None:
    """``set name`` after a closed ``config system snmp community`` block stays."""
    text = (
        'config system snmp community\n'
        '    edit 1\n'
        '        set name "FgCommInside"\n'
        '    next\n'
        'end\n'
        'config system interface\n'
        '    edit "port1"\n'
        '        set name "wan"\n'
        '    next\n'
        'end'
    )
    output = platform_redact.redact("fortios", text)
    assert 'set name "FgCommInside"' not in output
    assert 'set name <redacted>' in output
    assert 'set name "wan"' in output


def test_mv1_9_26_fortios_idempotence_and_placeholders() -> None:
    """Every FortiOS rule is idempotent and keeps existing placeholders."""
    text = (
        'config system snmp community\n'
        '    edit 1\n'
        '        set name "IdemComm26a"\n'
        '    next\n'
        'end\n'
        'config system admin\n'
        '    edit "admin"\n'
        '        set password ENC QUJDREVGRw==\n'
        '    next\n'
        'end\n'
        'config user radius\n'
        '    edit "R1"\n'
        '        set secret ENC QUJDRGFnU3ludGgyM2I=\n'
        '    next\n'
        'end\n'
        'config user tacacs+\n'
        '    edit "T1"\n'
        '        set key ENC QUJDREVGRw==\n'
        '    next\n'
        'end\n'
        'config vpn ipsec phase1-interface\n'
        '    edit "P1"\n'
        '        set psksecret "IdemPsk26b"\n'
        '        set psksecret-remote IdemSynth26c\n'
        '        set ppk-secret IdemSynth26d\n'
        '    next\n'
        'end\n'
        'config system snmp user\n'
        '    edit "U1"\n'
        '        set auth-pwd ENC QUJDRGFnU3ludGgyM2I=\n'
        '        set priv-pwd ENC QUJDREVGRw==\n'
        '        set auth-password IdemSynth26e\n'
        '    next\n'
        'end\n'
        'config system ntp\n'
        '    set key ENC QUJDREVGRw==\n'
        'end\n'
        'config system ha\n'
        '    set password IdemSynth26f\n'
        'end\n'
        'set passphrase IdemSynth26g\n'
        'config user ldap\n'
        '    edit "L1"\n'
        '        set ldap-password IdemSynth26h\n'
        '        set sso-password IdemSynth26i\n'
        '    next\n'
        'end\n'
        'set password ENC <redacted>\n'
        'set psksecret "<redacted:0a1b2c3d>"\n'
        'set name <redacted>\n'
    )
    once = platform_redact.redact("fortios", text)
    twice = platform_redact.redact("fortios", once)
    assert twice == once, "fortios platform redaction is not idempotent"
    for fragment in (
        "IdemComm26a", "QUJDREVGRw==", "QUJDRGFnU3ludGgyM2I=",
        "IdemPsk26b", "IdemSynth26c", "IdemSynth26d", "IdemSynth26e",
        "IdemSynth26f", "IdemSynth26g", "IdemSynth26h", "IdemSynth26i",
    ):
        assert fragment not in once, f"leaked secret: {fragment!r}"
    # Pin the placeholder lines byte-identical.
    assert "set password ENC <redacted>" in once
    assert 'set psksecret "<redacted:0a1b2c3d>"' in once
    assert "set name <redacted>" in once


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("set password \"" + "x" * 199_000, id="fortios-password-unclosed-quote"),
        pytest.param("ENC " * 100_000, id="fortios-enc-no-value"),
        pytest.param(
            "\n".join("config system snmp community" for _ in range(20_000)) + "\n",
            id="fortios-snmp-community-no-end",
        ),
    ],
)
def test_mv1_9_27_fortios_rules_are_linear_time(text: str) -> None:
    """Each FortiOS rule stays linear on 200 KB of stress input."""
    start = time.perf_counter()
    platform_redact.redact("fortios", text)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"redact took {elapsed:.3f}s"


_SNMP_BLOCK_TEXT = (
    'config system snmp community\n'
    '    edit 1\n'
    '        set name "IsolationComm28"\n'
    '    next\n'
    'end'
)


@pytest.mark.parametrize(
    ("platform", "text", "expected"),
    [
        pytest.param(
            "iosxe",
            "set psksecret ENC QUJDREVGRw==",
            "set psksecret ENC QUJDREVGRw==",
            id="iosxe-psksecret-enc-unchanged",
        ),
        pytest.param(
            "iosxe",
            _SNMP_BLOCK_TEXT,
            _SNMP_BLOCK_TEXT,
            id="iosxe-snmp-community-unchanged",
        ),
        pytest.param(
            "eos",
            "set psksecret ENC QUJDREVGRw==",
            "set psksecret ENC QUJDREVGRw==",
            id="eos-psksecret-enc-unchanged",
        ),
        pytest.param(
            "eos",
            _SNMP_BLOCK_TEXT,
            _SNMP_BLOCK_TEXT,
            id="eos-snmp-community-unchanged",
        ),
        pytest.param(
            "junos",
            "set psksecret ENC QUJDREVGRw==",
            "set psksecret ENC QUJDREVGRw==",
            id="junos-psksecret-enc-unchanged",
        ),
        pytest.param(
            "junos",
            _SNMP_BLOCK_TEXT,
            _SNMP_BLOCK_TEXT,
            id="junos-snmp-community-unchanged",
        ),
        pytest.param(
            "vyos",
            "set psksecret ENC QUJDREVGRw==",
            "set psksecret ENC QUJDREVGRw==",
            id="vyos-psksecret-enc-unchanged",
        ),
        pytest.param(
            "vyos",
            _SNMP_BLOCK_TEXT,
            _SNMP_BLOCK_TEXT,
            id="vyos-snmp-community-unchanged",
        ),
        pytest.param(
            "routeros",
            "set psksecret ENC QUJDREVGRw==",
            "set psksecret ENC QUJDREVGRw==",
            id="routeros-psksecret-enc-unchanged",
        ),
        pytest.param(
            "routeros",
            _SNMP_BLOCK_TEXT,
            _SNMP_BLOCK_TEXT,
            id="routeros-snmp-community-unchanged",
        ),
        pytest.param(
            "openwrt",
            "set psksecret ENC QUJDREVGRw==",
            "set psksecret ENC QUJDREVGRw==",
            id="openwrt-psksecret-enc-unchanged",
        ),
        pytest.param(
            "openwrt",
            _SNMP_BLOCK_TEXT,
            _SNMP_BLOCK_TEXT,
            id="openwrt-snmp-community-unchanged",
        ),
    ],
)
def test_mv1_9_28_fortios_does_not_change_other_platforms(
    platform: str, text: str, expected: str
) -> None:
    """The fortios branch must leave the other platforms byte-identical."""
    assert platform_redact.redact(platform, text) == expected


# ---- per-rule exact-output pins and mutation coverage -------


def test_mv1_9_29_iosxe_standby_md5_pins_exact_output() -> None:
    """``standby ... authentication md5 key-string 7 X`` pins the
    ``(?!md5...)`` exclusion on the standby rule: the ``md5`` / ``key-string`` /
    ``7`` tokens must stay, and only ``X`` becomes ``<redacted>``."""
    text = "standby 1 authentication md5 key-string 7 HsrpSynth29q"
    direct = platform_redact.redact("iosxe", text)
    assert direct == "standby 1 authentication md5 key-string 7 <redacted>", direct
    assert "HsrpSynth29q" not in direct


@pytest.mark.parametrize(
    "text",
    [
        pytest.param('set comments "XENC foo"', id="pin-enc-prefix-x"),
        pytest.param('set comments "ENCX foo"', id="pin-enc-suffix-x"),
        pytest.param('set alias "my-ENC foo"', id="pin-enc-hyphen-prefix"),
        pytest.param('set alias "ENC_x foo"', id="pin-enc-underscore-suffix"),
    ],
)
def test_mv1_9_29_fortios_enc_whole_word_guards_are_byte_identical(
    text: str,
) -> None:
    """Each ``ENC`` whole-word guard (lookbehind / lookahead) keeps
    a value that merely contains ``ENC`` byte-identical on the fortios branch."""
    assert platform_redact.redact("fortios", text) == text


def test_mv1_9_30_iosxe_standby_md5_keyword_is_preserved() -> None:
    """Mutation check h: the ``(?!md5...)`` exclusion on the standby
    rule must keep ``md5`` as a keyword.  Without the exclusion the standby
    rule redacts ``md5`` itself, so this test turns red on that mutation."""
    text = "standby 1 authentication md5 <redacted>"
    direct = platform_redact.redact("iosxe", text)
    assert "md5 <redacted>" in direct, direct
    assert direct.count("<redacted>") == 1, direct


def test_mv1_9_31_iosxe_standby_md5_x_double_redaction() -> None:
    """A stray secret after the ``md5`` keyword still redacts via
    rule 1, but ``md5`` itself must not be over-redacted by the standby rule."""
    text = "standby 1 authentication md5 LeadSynth31"
    direct = platform_redact.redact("iosxe", text)
    assert "LeadSynth31" not in direct, direct
    assert "standby 1 authentication md5 <redacted>" == direct, direct


def test_mv1_9_32_iosxe_glbp_rule_exact_output() -> None:
    """The new ``glbp`` rule produces exactly the documented output
    for every labelled form (rule 1 still handles ``md5 key-string``)."""
    cases = (
        (
            "glbp 1 authentication text GlbpSynth32a",
            "glbp 1 authentication text <redacted>",
        ),
        (
            "glbp 1 authentication text 0 GlbpSynth32b",
            "glbp 1 authentication text 0 <redacted>",
        ),
        (
            "glbp 1 authentication text 7 GlbpSynth32c",
            "glbp 1 authentication text 7 <redacted>",
        ),
        (
            "glbp 10 authentication md5 key-string 7 GlbpSynth32d",
            "glbp 10 authentication md5 key-string 7 <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_33_iosxe_ipsec_rule_exact_output() -> None:
    """The new ipsec rules produce exactly the documented output;
    ``ipsec``, ``spi``, the spi number, ``esp``, the cipher, the size, ``null``,
    ``md5``/``sha1`` and the type tokens all stay byte-identical."""
    cases = (
        (
            "ipv6 ospf authentication ipsec spi 500 sha1 IpsecSynth33a",
            "ipv6 ospf authentication ipsec spi 500 sha1 <redacted>",
        ),
        (
            "ospfv3 1 encryption ipsec spi 256 esp aes-cbc 128 EspSynth33b sha1 EspSynth33c",
            "ospfv3 1 encryption ipsec spi 256 esp aes-cbc 128 <redacted> sha1 <redacted>",
        ),
        (
            "area 0 authentication ipsec spi 256 sha1 0 IpsecSynth33d",
            "area 0 authentication ipsec spi 256 sha1 0 <redacted>",
        ),
        (
            "ipv6 ospf encryption ipsec spi 300 esp 3des 7 EspSynth33e md5 7 EspSynth33f",
            "ipv6 ospf encryption ipsec spi 300 esp 3des 7 <redacted> md5 7 <redacted>",
        ),
        (
            "ospfv3 encryption ipsec spi 301 esp des EspSynth33g sha1 EspSynth33h",
            "ospfv3 encryption ipsec spi 301 esp des <redacted> sha1 <redacted>",
        ),
        (
            "ospfv3 encryption ipsec spi 302 esp null sha1 EspSynth33i",
            "ospfv3 encryption ipsec spi 302 esp null sha1 <redacted>",
        ),
        (
            "ospfv3 encryption ipsec spi 303 esp aes-cbc 256 EspSynth33j sha1 EspSynth33k",
            "ospfv3 encryption ipsec spi 303 esp aes-cbc 256 <redacted> sha1 <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_34_iosxe_set_key_rule_exact_output() -> None:
    """The new ``set-key ascii|hex [0|8] <value>`` rule produces
    exactly the documented output."""
    cases = (
        (
            "security wpa psk set-key ascii 0 WlanSynth34a",
            "security wpa psk set-key ascii 0 <redacted>",
        ),
        (
            "security wpa psk set-key hex 8 WlanSynth34b",
            "security wpa psk set-key hex 8 <redacted>",
        ),
        (
            "security wpa psk set-key ascii WlanSynth34c",
            "security wpa psk set-key ascii <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


# ---- auth/priv ReDoS regression, case-insensitive coverage,
#      and Cisco TrustSec ``sap pmk`` rule -------------------------------


def test_mv1_9_35_iosxe_cts_sap_pmk_rule_exact_output() -> None:
    """The new ``sap pmk <hex-key> [mode-list <modes...>]`` rule produces
    exactly the documented output, preserving ``sap``, ``pmk``, ``mode-list``
    and every mode token."""
    cases = (
        (
            "sap pmk 0123ABCDCtsSynth35i mode-list gcm-encrypt gmac",
            "sap pmk <redacted> mode-list gcm-encrypt gmac",
        ),
        (
            "sap pmk 0123ABCDCtsSynth35j",
            "sap pmk <redacted>",
        ),
        (
            " SAP PMK 0123ABCDCtsSynth35k mode-list null",
            " SAP PMK <redacted> mode-list null",
        ),
        (
            "Sap Pmk 0123ABCDEFCtsSynth35l Mode-List Gcm-Encrypt Gmac",
            "Sap Pmk <redacted> Mode-List Gcm-Encrypt Gmac",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_36_iosxe_cts_sap_pmk_placeholder_passes_through() -> None:
    """A ``sap pmk <placeholder> mode-list ...`` line stays byte-identical
    under the rule 6 / set-key placeholder convention; only the bare hex key is
    redacted with ``<redacted>``."""
    cases = (
        (
            "sap pmk <redacted> mode-list gcm-encrypt gmac",
            "sap pmk <redacted> mode-list gcm-encrypt gmac",
        ),
        (
            "sap pmk <redacted:0a1b2c3d> mode-list gcm-encrypt gmac",
            "sap pmk <redacted:0a1b2c3d> mode-list gcm-encrypt gmac",
        ),
        (
            "sap pmk <redacted>",
            "sap pmk <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


# ---- blocking leaks from, rare leaks, mutant coverage


IOSXE_FORMS = (
    # Blocking leak 1: RADIUS dynamic-author ``server-key``.  The
    # ``-key`` suffix breaks rule 1's ``(?<![A-Za-z0-9_-])key`` lookbehind,
    # so a dedicated rule is required.
    pytest.param(
        " client 10.1.1.1 server-key 7 0822455D0A16",
        ("0822455D0A16",),
        id="r6-server-key-dynamic-author-7",
    ),
    pytest.param(
        "server-key 0 SrvKey40a",
        ("SrvKey40a",),
        id="r6-server-key-no-leading-space-0",
    ),
    pytest.param(
        "server-key SrvKey40b",
        ("SrvKey40b",),
        id="r6-server-key-no-type",
    ),
    pytest.param(
        "server-key 6 SrvKey40c",
        ("SrvKey40c",),
        id="r6-server-key-6",
    ),
    pytest.param(
        "SERVER-KEY 7 SrvKey40cU",
        ("SrvKey40cU",),
        id="r6-server-key-upper-case",
    ),
    pytest.param(
        "Server-Key 0 SrvKey40cM",
        ("SrvKey40cM",),
        id="r6-server-key-mixed-case",
    ),
    pytest.param(
        "server-key\t7\tSrvKey40cTab",
        ("SrvKey40cTab",),
        id="r6-server-key-tab-separator",
    ),
    pytest.param(
        "server-key  7  SrvKey40cDS",
        ("SrvKey40cDS",),
        id="r6-server-key-double-space",
    ),
    pytest.param(
        "server-key 7 <redacted:0a1b2c3d>",
        (),
        id="r6-server-key-placeholder-passes-through",
    ),
    # Blocking leak 2: EIGRP named-mode HMAC-SHA-256 keys.
    pytest.param(
        "  authentication mode hmac-sha-256 7 SyN7xQ40c",
        ("SyN7xQ40c",),
        id="r6-eigrp-hmac-sha-256-7",
    ),
    pytest.param(
        "authentication mode hmac-sha-256 0 SyN40d",
        ("SyN40d",),
        id="r6-eigrp-hmac-sha-256-0",
    ),
    pytest.param(
        "authentication mode hmac-sha-256 SyN40e",
        ("SyN40e",),
        id="r6-eigrp-hmac-sha-256-no-type",
    ),
    pytest.param(
        "AUTHENTICATION MODE HMAC-SHA-256 7 SyN40eU",
        ("SyN40eU",),
        id="r6-eigrp-hmac-sha-256-upper",
    ),
    pytest.param(
        "Authentication Mode hmac-sha-256\t7\tSyN40eTab",
        ("SyN40eTab",),
        id="r6-eigrp-hmac-sha-256-tab",
    ),
    pytest.param(
        "authentication mode hmac-sha-256  <redacted:0a1b2c3d>",
        (),
        id="r6-eigrp-hmac-sha-256-placeholder",
    ),
    # Blocking leak 3: MSDP ``ip msdp password peer <addr> [type] <value>``.
    pytest.param(
        "ip msdp password peer 10.1.1.1 7 SyN7xQ40f",
        ("SyN7xQ40f",),
        id="r6-msdp-password-peer-addr-7",
    ),
    pytest.param(
        "ip msdp vrf V password peer 10.1.1.1 0 Msdp40g",
        ("Msdp40g",),
        id="r6-msdp-vrf-password-peer-0",
    ),
    pytest.param(
        "ip msdp password peer 10.1.1.1 Msdp40h",
        ("Msdp40h",),
        id="r6-msdp-password-peer-no-type",
    ),
    pytest.param(
        "IP MSDP PASSWORD PEER 10.1.1.1 7 Msdp40gU",
        ("Msdp40gU",),
        id="r6-msdp-upper-case",
    ),
    pytest.param(
        "ip msdp password\tpeer\t10.1.1.1\t7\tMsdp40gTab",
        ("Msdp40gTab",),
        id="r6-msdp-tab-separator",
    ),
    pytest.param(
        "ip msdp password peer 10.1.1.1 7 <redacted:0a1b2c3d>",
        (),
        id="r6-msdp-placeholder",
    ),
    # Rare leak 4: NTP ``ntp authentication-key <id> <alg> [0|7] <key>``.
    pytest.param(
        "ntp authentication-key 1 sha1 NtpKey40i",
        ("NtpKey40i",),
        id="r6-ntp-sha1",
    ),
    pytest.param(
        "ntp authentication-key 2 sha2 7 NtpKey40j",
        ("NtpKey40j",),
        id="r6-ntp-sha2-7",
    ),
    pytest.param(
        "ntp authentication-key 3 cmac-aes-128 NtpKey40k",
        ("NtpKey40k",),
        id="r6-ntp-cmac-aes-128",
    ),
    pytest.param(
        "ntp authentication-key 4 md5 7 NtpKey40l",
        ("NtpKey40l",),
        id="r6-ntp-md5-7-keep-key-id",
    ),
    pytest.param(
        "ntp authentication-key 5 md5 NtpKey40m",
        ("NtpKey40m",),
        id="r6-ntp-md5-no-type-keep-key-id",
    ),
    pytest.param(
        "NTP AUTHENTICATION-KEY 1 SHA1 NtpKey40iU",
        ("NtpKey40iU",),
        id="r6-ntp-sha1-upper",
    ),
    pytest.param(
        "ntp authentication-key\t1\tsha1\tNtpKey40iTab",
        ("NtpKey40iTab",),
        id="r6-ntp-tab-separator",
    ),
    pytest.param(
        "ntp authentication-key 1 sha1 <redacted:0a1b2c3d>",
        (),
        id="r6-ntp-placeholder",
    ),
    # Rare leak 5: LDP ``mpls ldp password fallback [0|7] <value>``.
    pytest.param(
        "mpls ldp password fallback LdpKey40l",
        ("LdpKey40l",),
        id="r6-ldp-password-fallback",
    ),
    pytest.param(
        "mpls ldp password fallback 7 LdpKey40m",
        ("LdpKey40m",),
        id="r6-ldp-password-fallback-7",
    ),
    pytest.param(
        "MPLS LDP PASSWORD FALLBACK 7 LdpKey40mU",
        ("LdpKey40mU",),
        id="r6-ldp-upper-case",
    ),
    pytest.param(
        "mpls ldp password\tfallback\tLdpKey40mTab",
        ("LdpKey40mTab",),
        id="r6-ldp-tab-separator",
    ),
    pytest.param(
        "mpls ldp password fallback <redacted:0a1b2c3d>",
        (),
        id="r6-ldp-placeholder",
    ),
    # Rare leak 6: ``wpa-psk ascii|hex [0|7|8] X``.  Type 8 was rejected
    # by the ``[0|7]`` type token; the fix widens it to ``[0|7|8]``.
    pytest.param(
        "wpa-psk ascii 8 WpaKey40n",
        ("WpaKey40n",),
        id="r6-wpa-psk-ascii-8",
    ),
    pytest.param(
        "wpa-psk hex 8 WpaKey40o",
        ("WpaKey40o",),
        id="r6-wpa-psk-hex-8",
    ),
    pytest.param(
        "WPA-PSK ASCII 8 WpaKey40pU",
        ("WpaKey40pU",),
        id="r6-wpa-psk-upper-case",
    ),
    pytest.param(
        "wpa-psk ascii\t8\tWpaKey40pTab",
        ("WpaKey40pTab",),
        id="r6-wpa-psk-tab-separator",
    ),
    pytest.param(
        "wpa-psk ascii 8 <redacted:0a1b2c3d>",
        (),
        id="r6-wpa-psk-placeholder",
    ),
    # Rare leak 7: ``vrrp|glbp <n> authentication X`` (old no-keyword form).
    pytest.param(
        "vrrp 1 authentication VrrpKey40o",
        ("VrrpKey40o",),
        id="r6-vrrp-authentication-old-form",
    ),
    pytest.param(
        "glbp 1 authentication GlbpKey40p",
        ("GlbpKey40p",),
        id="r6-glbp-authentication-old-form",
    ),
    pytest.param(
        "VRRP 1 AUTHENTICATION VrrpKey40oU",
        ("VrrpKey40oU",),
        id="r6-vrrp-old-form-upper-case",
    ),
    pytest.param(
        "vrrp 1 authentication\tVrrpKey40oTab",
        ("VrrpKey40oTab",),
        id="r6-vrrp-old-form-tab-separator",
    ),
    pytest.param(
        "vrrp 1 authentication <redacted:0a1b2c3d>",
        (),
        id="r6-vrrp-old-form-placeholder",
    ),
    pytest.param(
        "glbp 1 authentication <redacted:0a1b2c3d>",
        (),
        id="r6-glbp-old-form-placeholder",
    ),
)


@pytest.mark.parametrize(("text", "secrets"), IOSXE_FORMS)
def test_mv1_9_46_iosxe_r6_leak_fixes_redact_synthetic_secrets(
    text: str, secrets: tuple[str, ...]
) -> None:
    """Every new r6 form (server-key, eigrp hmac-sha-256, MSDP,
    NTP, LDP, wpa-psk [0|7|8], vrrp/glbp old authentication form) redacts
    its synthetic secret under both platform and shared redaction."""
    direct = platform_redact.redact("iosxe", text)
    combined = redact.redact_text(direct)
    for value in secrets:
        assert value not in direct, f"direct leak: {value!r} in {direct!r}"
        assert value not in combined, f"shared leak: {value!r} in {combined!r}"
    # For placeholder cases, secret tuple is empty; line stays byte-identical
    # and either absorbs the placeholder (it stays as a token) or, when the
    # placeholder covers the post-keyword value, the existing redactor's
    # ``rule6_sub`` placeholder convention keeps it untouched.
    if not secrets:
        assert "<redacted" in direct or "<redacted" in combined


def test_mv1_9_47_iosxe_server_key_exact_outputs() -> None:
    """Each ``server-key`` form produces exactly the documented
    output: ``server-key``, ``7``, the address, the type token (when present)
    and the white-space separators all stay byte-identical."""
    cases = (
        (
            " client 10.1.1.1 server-key 7 0822455D0A16",
            " client 10.1.1.1 server-key 7 <redacted>",
        ),
        (
            "server-key 0 SrvKey47a",
            "server-key 0 <redacted>",
        ),
        (
            "server-key SrvKey47b",
            "server-key <redacted>",
        ),
        (
            "server-key 6 SrvKey47c",
            "server-key 6 <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_48_iosxe_eigrp_hmac_sha_256_exact_outputs() -> None:
    """Each ``authentication mode hmac-sha-256`` form produces
    exactly the documented output."""
    cases = (
        (
            "  authentication mode hmac-sha-256 7 EigrpSynth48a",
            "  authentication mode hmac-sha-256 7 <redacted>",
        ),
        (
            "authentication mode hmac-sha-256 0 EigrpSynth48b",
            "authentication mode hmac-sha-256 0 <redacted>",
        ),
        (
            "authentication mode hmac-sha-256 EigrpSynth48c",
            "authentication mode hmac-sha-256 <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_49_iosxe_msdp_exact_outputs() -> None:
    """Each MSDP form produces exactly the documented output:
    ``msdp``, ``password``, ``peer``, the address, and the type token stay."""
    cases = (
        (
            "ip msdp password peer 10.1.1.1 7 MsdpSynth49a",
            "ip msdp password peer 10.1.1.1 7 <redacted>",
        ),
        (
            "ip msdp vrf V password peer 10.1.1.1 0 MsdpSynth49b",
            "ip msdp vrf V password peer 10.1.1.1 0 <redacted>",
        ),
        (
            "ip msdp password peer 10.1.1.1 MsdpSynth49c",
            "ip msdp password peer 10.1.1.1 <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_50_iosxe_ntp_exact_outputs() -> None:
    """Each NTP form produces exactly the documented output:
    ``ntp``, ``authentication-key``, the key id, and the algorithm token
    stay; only the trailing secret becomes ``<redacted>``."""
    cases = (
        (
            "ntp authentication-key 1 sha1 NtpSynth50a",
            "ntp authentication-key 1 sha1 <redacted>",
        ),
        (
            "ntp authentication-key 2 sha2 7 NtpSynth50b",
            "ntp authentication-key 2 sha2 7 <redacted>",
        ),
        (
            "ntp authentication-key 3 cmac-aes-128 NtpSynth50c",
            "ntp authentication-key 3 cmac-aes-128 <redacted>",
        ),
        (
            "ntp authentication-key 4 md5 7 NtpSynth50d",
            "ntp authentication-key 4 md5 7 <redacted>",
        ),
        (
            "ntp authentication-key 5 md5 NtpSynth50e",
            "ntp authentication-key 5 md5 <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_51_iosxe_ldp_exact_outputs() -> None:
    """Each ``mpls ldp password fallback`` form produces the
    documented output: ``mpls``, ``ldp``, ``password``, ``fallback`` and
    the type token stay."""
    cases = (
        (
            "mpls ldp password fallback LdpSynth51a",
            "mpls ldp password fallback <redacted>",
        ),
        (
            "mpls ldp password fallback 7 LdpSynth51b",
            "mpls ldp password fallback 7 <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_52_iosxe_wpa_psk_type_8_exact_outputs() -> None:
    """``wpa-psk ascii|hex [0|7|8] X`` keeps the keyword,
    the ``ascii``/``hex`` token, and the type token; only the secret
    becomes ``<redacted>``."""
    cases = (
        (
            "wpa-psk ascii 8 WpaSynth52a",
            "wpa-psk ascii 8 <redacted>",
        ),
        (
            "wpa-psk hex 8 WpaSynth52b",
            "wpa-psk hex 8 <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_53_iosxe_vrrp_glbp_old_form_exact_outputs() -> None:
    """``vrrp|glbp <n> authentication X`` (no ``text`` keyword)
    redacts only the trailing secret; ``text``, ``md5`` and ``key-chain``
    after ``authentication`` stay byte-identical."""
    cases = (
        (
            "vrrp 1 authentication VrrpSynth53a",
            "vrrp 1 authentication <redacted>",
        ),
        (
            "glbp 1 authentication GlbpSynth53a",
            "glbp 1 authentication <redacted>",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


IOSXE_NEAR_MISSES = (
    # server-key: glued neighbours and other "key" prefixes stay byte-identical.
    pytest.param("xserver-key 7 SrvKey54a", id="near-miss-xserver-key-glued"),
    pytest.param("server-keyfoo 7 SrvKey54b", id="near-miss-server-keyfoo-suffix"),
    # EIGRP hmac-sha-256 near-miss: ``authentication mode md5`` and
    # ``authentication key-chain EIGRP-KEYS`` carry no secret value.
    pytest.param(
        "authentication mode md5",
        id="near-miss-authentication-mode-md5",
    ),
    pytest.param(
        "authentication key-chain EIGRP-KEYS",
        id="near-miss-authentication-key-chain",
    ),
    pytest.param(
        "authentication mode sha-256",
        id="near-miss-authentication-mode-sha-256-not-hmac",
    ),
    # MSDP near-miss: ``msdp mesh-group`` and ``msdp peer`` (without
    # ``password``) stay byte-identical; ``msdp password peer`` without
    # an address is malformed but should not redact ``peer``.
    pytest.param(
        "ip msdp mesh-group 1 10.1.1.1",
        id="near-miss-msdp-mesh-group",
    ),
    # NTP near-miss: ``ntp authentication-key 1 trusted`` has no secret
    # value and must stay byte-identical.
    pytest.param(
        "ntp authentication-key 1 trusted",
        id="near-miss-ntp-authentication-key-trusted",
    ),
    pytest.param(
        "ntp authenticate",
        id="near-miss-bare-ntp-authenticate",
    ),
    # LDP near-miss: ``mpls ldp neighbor 1.1.1.1 password fallback x``
    # without ``password fallback`` is not LDP secret syntax.
    pytest.param(
        "mpls ldp neighbor 1.1.1.1 password LdpNear54a",
        id="near-miss-mpls-ldp-neighbor-password-not-fallback",
    ),
    # VRRP / GLBP old form near-misses: ``text`` / ``md5`` / ``key-chain``
    # keywords after ``authentication`` are handled by existing rules and
    # stay byte-identical; HEAD's behaviour over-redacts ``key-chain``
    # after ``md5`` and we pin that output rather than change it.
    pytest.param(
        "vrrp 1 authentication text VrrpNear54a",
        id="near-miss-vrrp-authentication-text",
    ),
    pytest.param(
        "glbp 1 authentication text 7 GlbpNear54a",
        id="near-miss-glbp-authentication-text-7",
    ),
    pytest.param(
        "xvrrp 1 authentication VrrpNear54b",
        id="near-miss-xvrrp-not-whole-word",
    ),
    pytest.param(
        "glbpfoo 1 authentication GlbpNear54c",
        id="near-miss-glbpfoo-not-whole-word",
    ),
)


# HEAD outputs we pin rather than demand byte-identical.  These are
# cases where rule 1 over-redacts a non-secret neighbour token that the
# new r6 rules cannot defensively skip.
HEAD_OVERREDACTED = {
    "mpls ldp neighbor 1.1.1.1 password LdpNear54a":
        "mpls ldp neighbor 1.1.1.1 password <redacted>",
    "ntp authentication-key 1 trusted":
        "ntp authentication-key <redacted> trusted",
}


@pytest.mark.parametrize("text", IOSXE_NEAR_MISSES)
def test_mv1_9_54_iosxe_r6_whole_word_near_misses_are_byte_identical(
    text: str,
) -> None:
    """Each new r6 rule keeps glued / ``md5`` / ``key-chain``
    / wrong-keyword neighbours byte-identical.  ``vrrp 1 authentication
    text X`` is handled by the existing VRRP ``text`` rule and the new
    rule excludes the leading ``text`` keyword, so the existing output
    is preserved.  ``mpls ldp neighbor 1.1.1.1 password X`` and
    ``ntp authentication-key 1 trusted`` fall through to rule 1 because
    the new rules require a known neighbour shape; the test pins HEAD's
    output for those two cases so any future widening of rule 1 turns
    this red."""
    if text in HEAD_OVERREDACTED:
        assert platform_redact.redact("iosxe", text) == HEAD_OVERREDACTED[text], text
        return
    if isinstance(text, tuple):
        # ``(text, expected)`` -> pin the platform output exactly.  Used
        # for ``server-key chain X`` which the new rule redacts as if
        # ``chain`` were the secret; ``chain`` is unusual syntax in real
        # configs but the rule does not defensively exclude it (would
        # over-complicate the alternation), so the test pins what the
        # rule produces.
        text_, expected_ = text
        assert platform_redact.redact("iosxe", text_) == expected_, (text_, expected_)
        return
    if text in (
        "vrrp 1 authentication text VrrpNear54a",
        "glbp 1 authentication text 7 GlbpNear54a",
    ):
        # Existing rule 6 redacts ``text X``; the new rule must leave
        # it alone (or produce identical output).  Pin the platform
        # output exactly.
        assert platform_redact.redact("iosxe", text) == text.replace(
            "VrrpNear54a", "<redacted>"
        ).replace(
            "GlbpNear54a", "<redacted>"
        )
        return
    assert platform_redact.redact("iosxe", text) == text, text


def test_mv1_9_55_iosxe_vrrp_glbp_old_form_keyword_neighbours_pinned() -> None:
    """Pin HEAD's exact output for ``vrrp|glbp <n> authentication
    md5 key-chain X``.  The new rule excludes the leading ``md5`` keyword
    so it does not fire; rule 1 redacts ``X`` and the ``md5``/``key-chain``
    tokens survive exactly once each.  Removing the new MSDP-style
    exclusion or changing rule 1 turns this red."""
    cases = (
        (
            "vrrp 1 authentication md5 key-chain VRRP-KC",
            "vrrp 1 authentication md5 <redacted> VRRP-KC",
        ),
        (
            "glbp 1 authentication md5 key-chain GLBP-KC",
            "glbp 1 authentication md5 <redacted> GLBP-KC",
        ),
    )
    for text, expected in cases:
        assert platform_redact.redact("iosxe", text) == expected, (text, expected)


def test_mv1_9_56_iosxe_r6_idempotence_and_placeholders() -> None:
    """Every r6 callback is idempotent and lets a ``<redacted:0a1b2c3d>``
    placeholder survive verbatim."""
    text = (
        # server-key
        " client 10.1.1.1 server-key 7 IdemSrvKey56a\n"
        "server-key 0 IdemSrvKey56b\n"
        # EIGRP hmac-sha-256
        " authentication mode hmac-sha-256 7 IdemEigrp56a\n"
        # MSDP
        "ip msdp password peer 10.1.1.1 7 IdemMsdp56a\n"
        "ip msdp vrf V password peer 10.1.1.1 0 IdemMsdp56b\n"
        # NTP
        "ntp authentication-key 1 sha1 IdemNtp56a\n"
        "ntp authentication-key 2 sha2 7 IdemNtp56b\n"
        "ntp authentication-key 3 cmac-aes-128 IdemNtp56c\n"
        # LDP
        "mpls ldp password fallback 7 IdemLdp56a\n"
        # wpa-psk 8
        "wpa-psk ascii 8 IdemWpa56a\n"
        # VRRP / GLBP old auth
        "vrrp 1 authentication IdemVrrp56a\n"
        "glbp 1 authentication IdemGlbp56a\n"
        # Placeholders (already-redacted form)
        "server-key 7 <redacted:0a1b2c3d>\n"
        "authentication mode hmac-sha-256 7 <redacted:0a1b2c3d>\n"
        "ip msdp password peer 10.1.1.1 7 <redacted:0a1b2c3d>\n"
        "ntp authentication-key 1 sha1 <redacted:0a1b2c3d>\n"
        "mpls ldp password fallback 7 <redacted:0a1b2c3d>\n"
        "wpa-psk ascii 8 <redacted:0a1b2c3d>\n"
        "vrrp 1 authentication <redacted:0a1b2c3d>\n"
        "glbp 1 authentication <redacted:0a1b2c3d>\n"
    )
    once = platform_redact.redact("iosxe", text)
    twice = platform_redact.redact("iosxe", once)
    assert twice == once, "iosxe r6 platform redaction is not idempotent"
    for fragment in (
        "IdemSrvKey56a", "IdemSrvKey56b",
        "IdemEigrp56a",
        "IdemMsdp56a", "IdemMsdp56b",
        "IdemNtp56a", "IdemNtp56b", "IdemNtp56c",
        "IdemLdp56a",
        "IdemWpa56a",
        "IdemVrrp56a", "IdemGlbp56a",
    ):
        assert fragment not in once, f"leaked secret: {fragment!r}"
    # Placeholders stay byte-identical.
    for placeholder in (
        "server-key 7 <redacted:0a1b2c3d>",
        "authentication mode hmac-sha-256 7 <redacted:0a1b2c3d>",
        "ip msdp password peer 10.1.1.1 7 <redacted:0a1b2c3d>",
        "ntp authentication-key 1 sha1 <redacted:0a1b2c3d>",
        "mpls ldp password fallback 7 <redacted:0a1b2c3d>",
        "wpa-psk ascii 8 <redacted:0a1b2c3d>",
        "vrrp 1 authentication <redacted:0a1b2c3d>",
        "glbp 1 authentication <redacted:0a1b2c3d>",
    ):
        assert placeholder in once, f"lost placeholder: {placeholder!r}"


IOSXE_SEPARATORS = (
    # Generic secret rule: tab and double-space between keyword and value
    # must still redact.
    pytest.param(
        "secret\tSrvKey57a",
        ("SrvKey57a",),
        id="r6-secret-rule-tab",
    ),
    pytest.param(
        "secret  SrvKey57b",
        ("SrvKey57b",),
        id="r6-secret-rule-double-space",
    ),
    pytest.param(
        "key-string\t7\tKeyStr57a",
        ("KeyStr57a",),
        id="r6-key-string-rule-tab",
    ),
    pytest.param(
        "key-string  7  KeyStr57b",
        ("KeyStr57b",),
        id="r6-key-string-rule-double-space",
    ),
    pytest.param(
        "snmp-server community\tSrvKey57c",
        ("SrvKey57c",),
        id="r6-snmp-community-tab",
    ),
    pytest.param(
        "snmp-server community  SrvKey57d",
        ("SrvKey57d",),
        id="r6-snmp-community-double-space",
    ),
    pytest.param(
        "snmp-server user U G v3 auth\tsha\tSrvKey57e",
        ("SrvKey57e",),
        id="r6-snmp-user-auth-tab",
    ),
    pytest.param(
        "snmp-server user U G v3 auth  sha  SrvKey57f",
        ("SrvKey57f",),
        id="r6-snmp-user-auth-double-space",
    ),
    pytest.param(
        "snmp-server user U G v3 priv\taes\t128\tSrvKey57g",
        ("SrvKey57g",),
        id="r6-snmp-user-priv-tab",
    ),
    pytest.param(
        "snmp-server user U G v3 priv  aes  128  SrvKey57h",
        ("SrvKey57h",),
        id="r6-snmp-user-priv-double-space",
    ),
    pytest.param(
        "tacacs-server key\t7\tSrvKey57i",
        ("SrvKey57i",),
        id="r6-tacacs-key-tab",
    ),
    pytest.param(
        "tacacs-server key  7  SrvKey57j",
        ("SrvKey57j",),
        id="r6-tacacs-key-double-space",
    ),
    pytest.param(
        "radius-server key\t7\tSrvKey57k",
        ("SrvKey57k",),
        id="r6-radius-key-tab",
    ),
    pytest.param(
        "radius-server key  7  SrvKey57l",
        ("SrvKey57l",),
        id="r6-radius-key-double-space",
    ),
    # Also tab and double-space on the NEW rules from r6.
    pytest.param(
        "ip msdp password\tpeer\t10.1.1.1\t7\tSrvKey57m",
        ("SrvKey57m",),
        id="r6-msdp-tab",
    ),
    pytest.param(
        "ip msdp password  peer  10.1.1.1  7  SrvKey57n",
        ("SrvKey57n",),
        id="r6-msdp-double-space",
    ),
    pytest.param(
        "vrrp 1 authentication\tVrrpTab57a",
        ("VrrpTab57a",),
        id="r6-vrrp-old-form-tab",
    ),
    pytest.param(
        "vrrp 1 authentication  VrrpDS57a",
        ("VrrpDS57a",),
        id="r6-vrrp-old-form-double-space",
    ),
)


@pytest.mark.parametrize(("text", "secrets"), IOSXE_SEPARATORS)
def test_mv1_9_57_iosxe_tab_and_double_space_separators_redact_secrets(
    text: str, secrets: tuple[str, ...]
) -> None:
    """Tab and double-space separators between keyword and value
    redact just like single-space separators.  Covers the generic secret
    rule, key-string, snmp community, snmp user auth/priv, tacacs/radius
    key, MSDP and VRRP old auth form."""
    direct = platform_redact.redact("iosxe", text)
    for value in secrets:
        assert value not in direct, f"separator leak: {value!r} in {direct!r}"


IOSXE_CASE_FORMS = (
    # Verify-r3 case-insensitivity pinning for the 7 IOS XE rules the
    # mutate-the-flag mutant file names: WPA_PSK, SNMP_AUTH_GREEDY,
    # SNMP_PRIV, SNMP_PRIV_GREEDY, SNMP_HOST_BARE, NHRP_AUTH,
    # VRRP_AUTH_TEXT.  Each upper/mixed-case variant redacts.
    pytest.param(
        "WPA-PSK ASCII 7 IosCase58a",
        ("IosCase58a",),
        id="r6-wpa-psk-upper-case",
    ),
    pytest.param(
        "snmp-server user U G v3 AUTH SHA IosCase58b PRIV AES 128 IosCase58c",
        ("IosCase58b", "IosCase58c"),
        id="r6-snmp-auth-greedy-upper",
    ),
    pytest.param(
        "snmp-server user U G v3 auth sha 128x IosCase58d",
        ("IosCase58d", "128x"),
        id="r6-snmp-auth-greedy-mixed-128x",
    ),
    pytest.param(
        "SNMP-SERVER USER U G V3 PRIV AES IosCase58e",
        ("IosCase58e",),
        id="r6-snmp-priv-upper-case",
    ),
    pytest.param(
        "SNMP-SERVER USER U G V3 PRIV AES 128 IosCase58f",
        ("IosCase58f",),
        id="r6-snmp-priv-greedy-upper-case",
    ),
    pytest.param(
        "SNMP-SERVER HOST 192.0.2.5 IosCase58g",
        ("IosCase58g",),
        id="r6-snmp-host-bare-upper-case",
    ),
    pytest.param(
        "IP NHRP AUTHENTICATION SeCrEt58h",
        ("SeCrEt58h",),
        id="r6-nhrp-auth-upper-mixed",
    ),
    pytest.param(
        "ip nhrp Authentication SeCrEt58i",
        ("SeCrEt58i",),
        id="r6-nhrp-auth-mixed-case",
    ),
    pytest.param(
        "VRRP 1 AUTHENTICATION TEXT IosCase58j",
        ("IosCase58j",),
        id="r6-vrrp-auth-text-upper-case",
    ),
)


@pytest.mark.parametrize(("text", "secrets"), IOSXE_CASE_FORMS)
def test_mv1_9_58_iosxe_case_insensitive_r6_rules_redact_secrets(
    text: str, secrets: tuple[str, ...]
) -> None:
    """Upper/mixed-case forms of the 7 IOS XE rules the verify-r3
    mutants named redaction-gappy under ``re.IGNORECASE`` removal still
    redact on HEAD."""
    direct = platform_redact.redact("iosxe", text)
    for value in secrets:
        assert value not in direct, f"case-insensitive leak: {value!r} in {direct!r}"


def test_mv1_9_59_iosxe_r6_idempotence_callbacks_named_in_verify() -> None:
    """Idempotence (redact twice == once) for the five r6
    callbacks the verify file names as untested (server-key, hmac-sha-256,
    MSDP, NTP, LDP / wpa-psk, vrrp-old, glbp-old).  Each callback returns
    either the original match (when value is already a placeholder) or
    a substitution that preserves placeholders byte-identical."""
    # Build each callback's input / expected output triple.
    cases = (
        (
            "client 10.1.1.1 server-key 7 IdemSrvKey59a",
            "client 10.1.1.1 server-key 7 <redacted>",
        ),
        (
            "authentication mode hmac-sha-256 7 IdemEigrp59a",
            "authentication mode hmac-sha-256 7 <redacted>",
        ),
        (
            "ip msdp password peer 10.1.1.1 7 IdemMsdp59a",
            "ip msdp password peer 10.1.1.1 7 <redacted>",
        ),
        (
            "ntp authentication-key 1 sha1 IdemNtp59a",
            "ntp authentication-key 1 sha1 <redacted>",
        ),
        (
            "mpls ldp password fallback 7 IdemLdp59a",
            "mpls ldp password fallback 7 <redacted>",
        ),
        (
            "wpa-psk ascii 8 IdemWpa59a",
            "wpa-psk ascii 8 <redacted>",
        ),
        (
            "vrrp 1 authentication IdemVrrp59a",
            "vrrp 1 authentication <redacted>",
        ),
        (
            "glbp 1 authentication IdemGlbp59a",
            "glbp 1 authentication <redacted>",
        ),
    )
    for text, expected in cases:
        once = platform_redact.redact("iosxe", text)
        assert once == expected, (text, once)
        twice = platform_redact.redact("iosxe", once)
        assert twice == once, ("idempotence violated:", text, once)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "server-key 7 " + ("S" * 200_000),
            id="r6-server-key-200kb-no-value",
        ),
        pytest.param(
            "authentication mode hmac-sha-256 7 " + ("X" * 200_000),
            id="r6-eigrp-hmac-sha-256-200kb-no-value",
        ),
        pytest.param(
            "ip msdp password peer 10.1.1.1 7 " + ("Y" * 200_000),
            id="r6-msdp-200kb-no-value",
        ),
        pytest.param(
            "ntp authentication-key 1 sha1 " + ("Z" * 200_000),
            id="r6-ntp-sha1-200kb-no-value",
        ),
        pytest.param(
            "mpls ldp password fallback 7 " + ("Q" * 200_000),
            id="r6-ldp-200kb-no-value",
        ),
        pytest.param(
            "wpa-psk ascii 8 " + ("R" * 200_000),
            id="r6-wpa-psk-200kb-no-value",
        ),
        pytest.param(
            "vrrp 1 authentication " + ("V" * 200_000),
            id="r6-vrrp-200kb-no-value",
        ),
        pytest.param(
            "glbp 1 authentication " + ("G" * 200_000),
            id="r6-glbp-200kb-no-value",
        ),
    ],
)
def test_mv1_9_60_iosxe_r6_rules_are_linear_time(text: str) -> None:
    """Each new r6 rule stays linear (under 1 s) on 200 KB of input."""
    start = time.perf_counter()
    platform_redact.redact("iosxe", text)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"redact took {elapsed:.3f}s"


def test_mv1_9_61_iosxe_server_key_already_redacted_placeholder_survives() -> None:
    """A ``server-key 7 <redacted:0a1b2c3d>`` line stays
    byte-identical under the new rule; the placeholder callback re-uses
    the existing shared convention."""
    text = "client 10.1.1.1 server-key 7 <redacted:0a1b2c3d>"
    once = platform_redact.redact("iosxe", text)
    twice = platform_redact.redact("iosxe", once)
    assert once == text, once
    assert twice == once, twice


def test_mv1_9_62_iosxe_server_key_authentication_key_collision_safe() -> None:
    """``ip ospf authentication-key 7 X`` (rule 1 form) is NOT
    mistakenly redacted by the server-key rule; the lookbehind
    ``(?<![A-Za-z0-9_-])`` keeps ``authentication-key`` whole-word because
    the engine starts the rule 1 alternation at ``authentication-key``
    (matches the secret-word text), not at ``key``."""
    text = "ip ospf authentication-key 7 IosSynth62a"
    once = platform_redact.redact("iosxe", text)
    # Rule 1 fires on ``authentication-key`` (matches the secret-word text);
    # the server-key rule never fires because rule 1 owns the prefix.
    assert "IosSynth62a" not in once, once
    assert once == "ip ospf authentication-key 7 <redacted>", once


def test_mv1_9_63_iosxe_msdp_does_not_redact_when_peer_address_missing() -> None:
    """``ip msdp password peer`` without an address (malformed)
    is not the MSDP rule's shape, so rule 1 redacts ``peer`` (fail-safe
    over-redaction, as before r6)."""
    text = "ip msdp password peer"
    once = platform_redact.redact("iosxe", text)
    assert once == "ip msdp password <redacted>", once


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("enable password peer", "enable password <redacted>", id="password-is-peer"),
        pytest.param("username u password fallback", "username u password <redacted>", id="password-is-fallback"),
        pytest.param("ip msdp password peer 10.1.1.1 7", "ip msdp password peer 10.1.1.1 <redacted>", id="msdp-no-value"),
        pytest.param("ntp authentication-key 1 sha1", "ntp authentication-key <redacted> sha1", id="ntp-no-value"),
    ],
)
def test_mv1_9_69_iosxe_rule1_guards_only_skip_lines_already_redacted(text: str, expected: str) -> None:
    """Rule 1 skips ``password peer|fallback`` and the NTP
    ``authentication-key`` shape only when the r6 rule already put a
    placeholder there; otherwise rule 1 still redacts the next token."""
    assert platform_redact.redact("iosxe", text) == expected


def test_mv1_9_64_iosxe_ntp_does_not_redact_when_alg_unrecognised() -> None:
    """``ntp authentication-key 1 trusted`` has an unrecognised
    algorithm token, so the new NTP rule does not fire; rule 1 over-redacts
    the key id (``1``) with ``<redacted>`` because ``authentication-key``
    is in the secret-words list.  This pins HEAD's behaviour so a future
    widening of the NTP rule (to swallow unrecognised algorithms) turns
    this test red."""
    text = "ntp authentication-key 1 trusted"
    once = platform_redact.redact("iosxe", text)
    assert once == "ntp authentication-key <redacted> trusted", once
    # True byte-identical near-misses for the NTP rule:
    assert platform_redact.redact("iosxe", "ntp authenticate") == "ntp authenticate"
    assert platform_redact.redact("iosxe", "ntp authentication trusted") == "ntp authentication trusted"


def test_mv1_9_65_iosxe_ntp_rule_runs_before_rule1() -> None:
    """``ntp authentication-key 1 sha1 X`` keeps the key id and
    the algorithm token; only ``X`` becomes ``<redacted>``.  This is
    r6's verification that rule 1's `authentication-key <id>` over-redaction
    (which would redact ``1``) is no longer reached when the new NTP
    rule fires first."""
    text = "ntp authentication-key 1 sha1 IosSynth65a"
    once = platform_redact.redact("iosxe", text)
    assert once == "ntp authentication-key 1 sha1 <redacted>", once


def test_mv1_9_66_iosxe_vrrp_old_form_keeps_text_md5_neighbours() -> None:
    """The new VRRP old-auth-form rule does not match lines that
    contain a recognised keyword (``text`` / ``md5``) after
    ``authentication``; rule 1 / existing rule 6 still handle those cases."""
    cases = (
        "vrrp 1 authentication text Vrrp66a",
        "vrrp 1 authentication md5 key-chain VRRP-KC",
        "glbp 1 authentication text 7 Glbp66a",
        "glbp 1 authentication md5 key-chain GLBP-KC",
        # ``vrrp 1 authentication 7 X`` has no keyword after ``authentication``
        # but has the optional type token ``7``; the new VRRP rule treats it
        # as a type-then-secret pair and redacts the value.
        "vrrp 1 authentication 7 Vrrp66b",
    )
    assert platform_redact.redact("iosxe", cases[0]) == "vrrp 1 authentication text <redacted>"
    assert platform_redact.redact("iosxe", cases[1]) == "vrrp 1 authentication md5 <redacted> VRRP-KC"
    assert platform_redact.redact("iosxe", cases[2]) == "glbp 1 authentication text 7 <redacted>"
    assert platform_redact.redact("iosxe", cases[3]) == "glbp 1 authentication md5 <redacted> GLBP-KC"
    assert platform_redact.redact("iosxe", cases[4]) == "vrrp 1 authentication 7 <redacted>"


def test_mv1_9_67_iosxe_new_rules_leave_other_platforms_byte_identical() -> None:
    """The new r6 iosxe rules don't leak into the other branches;
    ``mv1-9-21`` and ``mv1-9-28`` isolation pins keep passing unchanged."""
    snippet = (
        " client 10.1.1.1 server-key 7 SrvKey67a\n"
        " authentication mode hmac-sha-256 7 SyN67a\n"
        "ip msdp password peer 10.1.1.1 7 Msdp67a\n"
        "ntp authentication-key 1 sha1 Ntp67a\n"
        "mpls ldp password fallback 7 Ldp67a\n"
        "wpa-psk ascii 8 Wpa67a\n"
        "vrrp 1 authentication Vrrp67a\n"
    )
    # vyos, eos and junos are left out: their own generic ``password
    # <word>`` rules already redact the msdp
    # and ldp lines; the iosxe-only diff cannot change them, and
    # The isolation tests pin their isolation.
    for platform in ("routeros", "fortios", "openwrt"):
        assert platform_redact.redact(platform, snippet) == snippet


def test_mv1_9_68_iosxe_msdp_rule_fires_before_rule1() -> None:
    """The MSDP rule fires BEFORE rule 1 so the rule 1 callback's
    ``password <value>`` cannot redact the ``peer`` token.  Pin both
    forms (with and without VRF) and the type-token variants."""
    cases = (
        (
            "ip msdp password peer 10.1.1.1 7 Peer68a",
            "ip msdp password peer 10.1.1.1 7 <redacted>",
        ),
        (
            "ip msdp password peer 10.1.1.1 Peer68b",
            "ip msdp password peer 10.1.1.1 <redacted>",
        ),
        (
            "ip msdp vrf V password peer 10.1.1.1 0 Peer68c",
            "ip msdp vrf V password peer 10.1.1.1 0 <redacted>",
        ),
    )
    for text, expected in cases:
        once = platform_redact.redact("iosxe", text)
        assert once == expected, (text, once)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        pytest.param("mpls ldp password fallback 6 LdpType6Fu1", "LdpType6Fu1", id="ldp-fallback-type6"),
        pytest.param("mpls ldp password fallback 8 LdpType8Fu2", "LdpType8Fu2", id="ldp-fallback-type8"),
        pytest.param("ntp authentication-key 4 sha1 6 NtpType6Fu3", "NtpType6Fu3", id="ntp-type6"),
        pytest.param("ntp authentication-key 5 md5 9 NtpType9Fu4", "NtpType9Fu4", id="ntp-type9"),
        pytest.param("wpa-psk ascii 6 WpaType6Fu5", "WpaType6Fu5", id="wpa-psk-type6"),
        pytest.param("wpa-psk ascii 9 WpaType9Fu6", "WpaType9Fu6", id="wpa-psk-type9"),
        pytest.param(" client 10.1.1.1 server-key 8 SrvType8Fu7", "SrvType8Fu7", id="server-key-type8"),
        pytest.param("  authentication mode hmac-sha-256 6 HmacType6Fu8", "HmacType6Fu8", id="eigrp-type6"),
        pytest.param("ip msdp password peer 10.1.1.1 9 MsdpType9Fu9", "MsdpType9Fu9", id="msdp-type9"),
        pytest.param("mpls ldp password option 1 for 10 7 LdpOptFu10", "LdpOptFu10", id="ldp-option-type7"),
        pytest.param("mpls ldp password option 2 for LDP-PEERS LdpOptFu11", "LdpOptFu11", id="ldp-option-plain"),
        pytest.param("MPLS LDP PASSWORD OPTION 3 FOR 10 0 LdpOptFu12", "LdpOptFu12", id="ldp-option-upper"),
        pytest.param("mpls ldp vrf V password option 1 for 10\tLdpOptFu13", "LdpOptFu13", id="ldp-option-vrf-tab"),
    ],
)
def test_mv1_9_70_iosxe_followup_type_tokens_and_ldp_option(text: str, secret: str) -> None:
    """Verify r4 notes 1-3: type 6/8/9 tokens on the r6 rules,
    and ``mpls ldp password option <n> for <acl> [type] X``."""
    once = platform_redact.redact("iosxe", text)
    assert secret not in once, once
    assert secret not in redact.redact_text(once), once
    assert platform_redact.redact("iosxe", once) == once


def test_mv1_9_71_iosxe_ldp_option_key_chain_is_not_a_secret() -> None:
    """The key-chain form names a chain, it carries no key; the
    LDP option rule leaves the chain name alone."""
    text = "mpls ldp password option 1 for 10 key-chain LDP-KC"
    assert "LDP-KC" in platform_redact.redact("iosxe", text)


def test_mv1_9_72_iosxe_ldp_option_exact_output() -> None:
    """Keywords, option number and ACL are kept."""
    out = platform_redact.redact("iosxe", "mpls ldp password option 1 for 10 7 LdpOptFu15")
    assert out.endswith("option 1 for 10 7 <redacted>"), out


# ---- the RouterOS export carries its own secrets -------------------------
#
# The backup of a vendor device is written by the platform redactor alone
# (the shared OpenWrt redactor runs on the getter lane, not on the vendor
# backup), so the RouterOS pass has to hide the secret-looking values of
# an ``/export`` text by itself.


ROUTEROS_EXPORT = "\n".join(
    [
        "# jan/01/2026 12:00:00 by RouterOS 7.24.5",
        "/ip address add address=10.109.0.21/24 interface=ether1 network=10.109.0.0",
        '/user add name=newton group=full password="RosPasswordSecret"',
        "/interface wireless security-profiles add name=lab "
        "wpa2-pre-shared-key=RosPresharedSecret",
        "/ip service set telnet disabled=yes",
        "/system identity set name=lab-chr",
    ]
)


@pytest.mark.parametrize(
    "line",
    [
        'add name=p1 password="RosPasswordSecret"',
        "add name=p1 password=RosPasswordSecret",
        "add name=p1 secret=RosSecretValue",
        "add name=p1 passphrase=RosPassphraseSecret",
        'add name=p1 private-key="RosPrivateSecret"',
        "add name=p1 wpa2-pre-shared-key=RosPresharedSecret",
        "add name=p1 pre-shared-key=RosPresharedSecret",
        "add name=p1 authentication-key=RosAuthKeySecret",
        "add name=p1 community=RosCommunitySecret",
        "add name=p1 key=RosKeySecret",
    ],
)
def test_routeros_export_secrets_are_hidden(line: str) -> None:
    """Every secret-looking parameter of an export is hidden."""
    value = line.split("=", 1)[1].strip('"')
    output = platform_redact.redact("routeros", line)

    assert value not in output
    assert "<redacted>" in output
    assert line.split("=", 1)[0] in output


def test_the_routeros_export_keeps_its_own_facts() -> None:
    """The export keeps everything that is not a secret."""
    output = platform_redact.redact("routeros", ROUTEROS_EXPORT)

    assert "address=10.109.0.21/24" in output
    assert "interface=ether1" in output
    assert "disabled=yes" in output
    assert "name=lab-chr" in output
    assert "RosPasswordSecret" not in output
    assert "RosPresharedSecret" not in output
    assert output.count("<redacted>") == 2


def test_routeros_near_misses_are_not_secrets() -> None:
    """A neighbour of a secret word carries no secret."""
    text = (
        "/certificate add name=ca common-name=lab public-key=ros-public "
        "key-id=0x1234"
    )
    assert platform_redact.redact("routeros", text) == text


def test_routeros_redaction_keeps_the_placeholders() -> None:
    """A placeholder is terminal, so a second pass changes nothing."""
    text = (
        "add name=p1 password=<redacted:0a1b2c3d>\n"
        "add name=p2 secret=<redacted>\n"
    )
    once = platform_redact.redact("routeros", text)

    assert "<redacted:0a1b2c3d>" in once
    assert "<redacted>" in once
    assert platform_redact.redact("routeros", once) == once


def test_routeros_redaction_joins_the_continuations_first() -> None:
    """A secret split over two lines is still hidden."""
    text = 'add name=p1 password="RosPassword\\\n    Secret"\n'
    output = platform_redact.redact("routeros", text)

    assert "RosPassword" not in output
    assert "Secret" not in output
    assert "<redacted>" in output


def test_the_routeros_rule_is_linear_time() -> None:
    """The new rule may not backtrack on a big export."""
    text = ("/ip address add address=10.109.0.21/24 interface=ether1 " * 20000)
    started = time.monotonic()
    platform_redact.redact("routeros", text)
    assert time.monotonic() - started < 5.0


# ---- the Junos display-set configuration ---------------------------------
#
# The backup of a Junos is written by the platform redactor alone, so the
# pass has to hide the secrets of a display-set configuration by itself.
#


JUNOS_DISPLAY_SET = "\n".join(
    [
        "set version 26.2R1.7",
        "set system host-name lab-junos",
        'set system root-authentication encrypted-password "$9$Synthetic9Hash"',
        'set system login user newton authentication encrypted-password "$6$Synthetic6Hash"',
        'set snmp community public authentication secret "$9$SyntheticSecret"',
        'set system services ssh host-key lab "ssh-ed25519 AAASyntheticKeyBody"',
        "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
        "set system services web-management http",
    ]
)


def test_the_junos_display_set_hides_every_secret() -> None:
    """Every secret of a display-set configuration is hidden."""
    output = platform_redact.redact("junos", JUNOS_DISPLAY_SET)

    assert "Synthetic9Hash" not in output
    assert "Synthetic6Hash" not in output
    assert "SyntheticSecret" not in output
    assert "AAASyntheticKeyBody" not in output
    assert output.count("<redacted>") >= 4


def test_the_junos_display_set_keeps_its_own_facts() -> None:
    """The configuration keeps everything that is not a secret."""
    output = platform_redact.redact("junos", JUNOS_DISPLAY_SET)

    assert "set version 26.2R1.7" in output
    assert "set system host-name lab-junos" in output
    assert "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24" in output
    assert "set system services web-management http" in output
    # the labels are kept: the owner has to see what was hidden
    assert "encrypted-password" in output
    assert "secret" in output


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        pytest.param(
            'set system root-authentication encrypted-password "$9$Synthetic9"',
            "Synthetic9",
            id="dollar-9-quoted",
        ),
        pytest.param(
            'set system root-authentication encrypted-password "$6$Synthetic6"',
            "Synthetic6",
            id="dollar-6-quoted",
        ),
        pytest.param(
            "set system login user newton authentication secret SyntheticPlain",
            "SyntheticPlain",
            id="secret-label",
        ),
        pytest.param(
            "set snmp community public authentication-key SyntheticKey",
            "SyntheticKey",
            id="authentication-key-label",
        ),
        pytest.param(
            'set system services ssh host-key lab "ssh-ed25519 AAASyntheticBody"',
            "AAASyntheticBody",
            id="ssh-ed25519-body",
        ),
        pytest.param(
            'set system services ssh host-key lab "ssh-rsa AAASyntheticRsa"',
            "AAASyntheticRsa",
            id="ssh-rsa-body",
        ),
    ],
)
def test_the_junos_secret_forms_are_hidden(
    text: str, secret: str
) -> None:
    """The secret forms of a Junos are hidden."""
    output = platform_redact.redact("junos", text)

    assert secret not in output
    assert "<redacted>" in output


def test_the_junos_redaction_keeps_the_placeholders() -> None:
    """A placeholder is terminal, so a second pass changes nothing."""
    text = (
        'set system root-authentication encrypted-password "<redacted>"\n'
        'set system services ssh host-key lab "ssh-ed25519 <redacted>"\n'
    )
    once = platform_redact.redact("junos", text)

    assert "<redacted>" in once
    assert platform_redact.redact("junos", once) == once


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "set system services ssh host-key lab ssh-ed25519",
            id="junos-key-type-alone",
        ),
        pytest.param(
            "set system login user newton class super-user",
            id="junos-class",
        ),
        pytest.param(
            "set system name-server 192.0.2.1",
            id="junos-name-server",
        ),
    ],
)
def test_junos_near_misses_are_not_secrets(text: str) -> None:
    """A neighbour of a secret word carries no secret."""
    assert platform_redact.redact("junos", text) == text


def test_the_junos_rule_is_linear_time() -> None:
    """The new rules may not backtrack on a big configuration."""
    text = ("set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24 " * 20000)
    started = time.monotonic()
    platform_redact.redact("junos", text)
    assert time.monotonic() - started < 5.0


# ---- the Junos display-set corpus of the secret labels -----------
#
# Review of the Junos pass found three labels that a display-set
# configuration carries and the pass did not know ("password",
# "preshared-key", "simple-password"), and an exemption that hid a
# secret whose value is only digits.
#


JUNOS_SECRET_LABELS = (
    pytest.param(
        "set system login user newton authentication password JunosPw",
        "JunosPw",
        id="password",
    ),
    pytest.param(
        "set security ike policy lab preshared-key JunosPsk",
        "JunosPsk",
        id="preshared-key",
    ),
    pytest.param(
        "set security ike gateway lab simple-password JunosSimple",
        "JunosSimple",
        id="simple-password",
    ),
    pytest.param(
        "set snmp community public authentication secret JunosSecret",
        "JunosSecret",
        id="secret",
    ),
    pytest.param(
        "set system root-authentication encrypted-password JunosEncrypted",
        "JunosEncrypted",
        id="encrypted-password",
    ),
    pytest.param(
        "set system root-authentication plain-text-password JunosPlain",
        "JunosPlain",
        id="plain-text-password",
    ),
    pytest.param(
        "set security ipsec vpn lab pre-shared-key JunosPreShared",
        "JunosPreShared",
        id="pre-shared-key",
    ),
    pytest.param(
        "set security ipsec vpn lab privacy-secret JunosPrivacy",
        "JunosPrivacy",
        id="privacy-secret",
    ),
)


@pytest.mark.parametrize(("text", "secret"), JUNOS_SECRET_LABELS)
def test_the_junos_secret_labels_are_hidden(
    text: str, secret: str
) -> None:
    """Every secret label of a display-set configuration is hidden."""
    output = platform_redact.redact("junos", text)

    assert secret not in output
    assert output.endswith("<redacted>")
    # the label is kept: the owner has to see what was hidden
    assert text.split()[-2] in output


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        pytest.param(
            "set snmp community public authentication secret 12345",
            "12345",
            id="secret-digits",
        ),
        pytest.param(
            "set system login user newton authentication password 987654",
            "987654",
            id="password-digits",
        ),
        pytest.param(
            "set security ike policy lab preshared-key 424242",
            "424242",
            id="preshared-key-digits",
        ),
        pytest.param(
            "set security ike gateway lab simple-password 111111",
            "111111",
            id="simple-password-digits",
        ),
    ],
)
def test_a_secret_that_is_only_digits_is_hidden(
    text: str, secret: str
) -> None:
    """A secret that is only digits is a secret like any other.

    The exemption for a value that is only digits belongs to the label
    whose value may be an index ("ntp authentication-key 1 sha1 ...").
    Under a secret label the value is a secret, digits or not.
    """
    output = platform_redact.redact("junos", text)

    assert secret not in output
    assert output.endswith("<redacted>")


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "set system ntp authentication-key 1",
            id="the-index-of-a-key",
        ),
        pytest.param(
            "set system login user newton class super-user",
            id="junos-class",
        ),
        pytest.param(
            "set system domain-password DomSynth",
            id="domain-password",
        ),
        pytest.param(
            "set system services ssh host-key lab ssh-ed25519",
            id="junos-key-type-alone",
        ),
    ],
)
def test_the_junos_near_misses_are_not_secrets(text: str) -> None:
    """A neighbour of a secret label carries no secret."""
    assert platform_redact.redact("junos", text) == text


def test_the_junos_corpus_of_the_shipped_fixtures_is_unchanged() -> None:
    """The shipped Junos fixtures carry no secret of the corpus.

    The fixtures of the device are read by the owner, so the pass must
    leave them byte-identical: none of them carries a secret label.
    """
    for path in sorted((FIXTURES_DIR / "junos").iterdir()):
        if not path.is_file() or "error" in path.name:
            continue
        text = path.read_text(encoding="utf-8")
        assert platform_redact.redact("junos", text) == text, path.name


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        pytest.param(
            "set system login user newton authentication password = JunosPw",
            "JunosPw",
            id="password-assignment",
        ),
        pytest.param(
            "set snmp community public authentication secret = JunosSecret",
            "JunosSecret",
            id="secret-assignment",
        ),
        pytest.param(
            "set security ike policy lab preshared-key = JunosPsk",
            "JunosPsk",
            id="preshared-key-assignment",
        ),
    ],
)
def test_an_assignment_is_left_to_the_shared_redactor(
    text: str, secret: str
) -> None:
    """The assignment form belongs to the shared redactor.

    A display-set configuration never carries an assignment, and the
    platform pass must not swallow the "=" of a "name = value" line:
    the value behind it would stay in the clear.  The shared redactor
    owns that form and hides the value.
    """
    after_platform = platform_redact.redact("junos", text)

    # the platform pass left the assignment alone
    assert secret in after_platform
    # and the shared redactor hides the value behind it
    assert secret not in redact.redact_text(after_platform)
