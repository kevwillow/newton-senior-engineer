"""the agent's explanation object (shape, text hygiene, masking, claims).

Design: explanation rules 1 and 4 (claims must map to existing
probes so the post-apply check can run them later).  Nothing here touches a device.
"""

from __future__ import annotations

import pytest

from exhelp import make_explanation
from newton_mcp import explanation as ex
from newton_mcp.probes import validate_probes

BATCH = "set firewall.fwd_8443=redirect\nset firewall.fwd_8443.dest_port='8443'"


def good(**overrides):
    return make_explanation(BATCH, **overrides)


def test_valid_explanation_round_trips_to_plain_json():
    out = ex.parse_explanation(good(), change_lines=2)
    assert set(out) == {"intent", "steps", "expect", "risk"}
    assert len(out["steps"]) == 2
    assert out["expect"] == [{"kind": "probe", "probe": ["iface-absent", "guestx"]}]
    # the stored form re-validates to itself (apply and newton-approve rely on this)
    assert ex.parse_explanation(out, change_lines=2) == out


def test_change_line_is_a_nonblank_noncomment_batch_line():
    assert ex.change_lines("set a.b=c\n\n# note\n  \n  set a.b.d=e  \n#x") == 2
    assert ex.change_lines("") == 0


@pytest.mark.parametrize("missing", ["intent", "steps", "expect", "risk"])
def test_every_field_is_required(missing):
    raw = good()
    del raw[missing]
    with pytest.raises(ex.ExplanationError) as err:
        ex.parse_explanation(raw, change_lines=2)
    assert missing in str(err.value)


def test_unknown_keys_and_wrong_types_refused():
    for raw in (good(extra="x"), good(intent=5), good(steps="one"), good(risk=None), "just text", None, [1]):
        with pytest.raises(ex.ExplanationError):
            ex.parse_explanation(raw, change_lines=2)


def test_steps_count_must_equal_change_lines_and_message_says_how_many():
    with pytest.raises(ex.ExplanationError) as err:
        ex.parse_explanation(good(steps=["only one"]), change_lines=2)
    assert "1" in str(err.value) and "2" in str(err.value) and "change line" in str(err.value)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(steps=["a", "b", "c"]), change_lines=2)


@pytest.mark.parametrize("field,limit", [("intent", 160), ("risk", 300)])
def test_length_limits_are_strict(field, limit):
    ex.parse_explanation(good(**{field: "x" * limit}), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(**{field: "x" * (limit + 1)}), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(**{field: "   "}), change_lines=2)


def test_step_length_and_empty_steps_refused():
    ex.parse_explanation(good(steps=["x" * 160, "y"]), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(steps=["x" * 161, "y"]), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(steps=["", "y"]), change_lines=2)


def test_step_cap_is_64():
    ex.parse_explanation(good(steps=["s"] * 64), change_lines=64)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(steps=["s"] * 65), change_lines=65)


@pytest.mark.parametrize("bad", [
    "line\x1b[31mred", "bell\x07", "nul\x00x", "tab\there", "cr\rhere", "newline\nhere",
    "del\x7fx", "c1\x9bx", "bidi‮evil", "zero​width", "sep x", "nbsp x",
])
def test_control_and_nonprinting_characters_are_refused(bad):
    for field in ("intent",):
        with pytest.raises(ex.ExplanationError) as err:
            ex.parse_explanation(good(**{field: bad}), change_lines=2)
        assert "printable" in str(err.value)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(steps=[bad, "ok"]), change_lines=2)


def test_risk_may_use_exactly_one_newline_for_two_lines():
    ex.parse_explanation(good(risk="First line.\nSecond line."), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(risk="a\nb\nc"), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(risk="a\n\nb"), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(risk="a\x1b[2J\nb"), change_lines=2)


def test_ordinary_non_ascii_text_is_allowed():
    out = ex.parse_explanation(good(intent="Öffne Port 8443 für den Drucker"), change_lines=2)
    assert out["intent"].startswith("Öffne")


def test_secrets_in_free_text_are_masked_before_storage():
    secret = "Hunter2-very-secret-value"
    raw = good(
        intent=f"Set wireless.ap.key='{secret}' on the guest network",
        steps=[f"Write wireless.ap.key={secret}", "Done"],
        risk=f"password: {secret}",
    )
    out = ex.parse_explanation(raw, change_lines=2)
    blob = repr(out)
    assert secret not in blob
    assert "<redacted:" in blob
    # re-validating the stored (masked) form is stable, so the hash is stable
    assert ex.parse_explanation(out, change_lines=2) == out


def test_expect_needs_one_to_eight_claims():
    claim = {"kind": "probe", "probe": ["iface-absent", "guestx"]}
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(expect=[]), change_lines=2)
    ex.parse_explanation(good(expect=[claim] * 8), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(expect=[claim] * 9), change_lines=2)


def test_uci_equals_claim_maps_to_the_uci_equals_probe():
    claim = {"kind": "uci_equals", "path": "firewall.fwd_8443.dest_port", "equals": "8443"}
    out = ex.parse_explanation(good(expect=[claim]), change_lines=2)
    assert out["expect"] == [claim]
    assert ex.claim_to_probe(out["expect"][0]) == ["uci-equals", "firewall.fwd_8443.dest_port", "8443"]
    assert validate_probes([ex.claim_to_probe(out["expect"][0])])


def test_probe_claim_maps_to_itself_and_is_validated_by_the_real_probe_table():
    claim = {"kind": "probe", "probe": ["service-running", "dnsmasq", "any"]}
    out = ex.parse_explanation(good(expect=[claim]), change_lines=2)
    assert ex.claim_to_probe(out["expect"][0]) == ["service-running", "dnsmasq", "any"]


@pytest.mark.parametrize("claim", [
    {"kind": "probe", "probe": ["no-such-probe", "x"]},
    {"kind": "probe", "probe": ["fail"]},                       # never true
    {"kind": "probe", "probe": []},
    {"kind": "probe", "probe": ["ping", "192.0.2.1", "9"]},     # bad arg per the real table
    {"kind": "probe", "probe": ["uci-equals", "wireless.ap.key", "x"]},   # secret option refused
    {"kind": "uci_equals", "path": "wireless.ap.key", "equals": "x"},
    {"kind": "uci_equals", "path": "firewall.fwd", "equals": "x"},        # needs cfg.section.option
    {"kind": "uci_equals", "path": "fire wall.x.y", "equals": "x"},
    {"kind": "uci_equals", "path": "firewall.x.y", "equals": "1; reboot\\"},
    {"kind": "uci_equals", "path": "firewall.x.y", "equals": "x" * 129},
    {"kind": "uci_equals", "path": "firewall.x.y", "equals": ""},
    {"kind": "uci_equals", "path": "firewall.x.y"},
    {"kind": "uci_equals", "path": "firewall.x.y", "equals": "1", "cmd": "reboot"},
    {"kind": "shell", "cmd": "reboot"},
    {"kind": "probe", "probe": "iface-absent guestx"},
    "uci get firewall.x.y == 1",
])
def test_bad_claims_are_refused(claim):
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(expect=[claim]), change_lines=2)


def test_a_claim_value_that_looks_like_a_secret_is_refused_not_stored():
    claim = {"kind": "uci_equals", "path": "network.lan.note", "equals": "password=abcdef123456"}
    with pytest.raises(ex.ExplanationError) as err:
        ex.parse_explanation(good(expect=[claim]), change_lines=2)
    assert "abcdef123456" not in str(err.value)


def test_error_text_never_echoes_agent_input():
    marker = "ZZ-MARKER-\x1b[31m"
    for raw in (good(intent=marker), good(extra_key_ZZ=marker), good(steps=[marker, "x"]),
                good(expect=[{"kind": "uci_equals", "path": marker, "equals": "1"}])):
        with pytest.raises(ex.ExplanationError) as err:
            ex.parse_explanation(raw, change_lines=2)
        assert "ZZ-MARKER" not in str(err.value)
        assert "\x1b" not in str(err.value)


def test_explanation_is_not_executable_anywhere_in_the_schema():
    # no claim kind carries a command string: only probe field lists, a uci path
    # + text, a vendor statement or a host name
    kinds = ex.CLAIM_KINDS
    # The five client kinds.  They name a kind and a zone (and, for
    # a blocked or reaches claim, the targets Newton derived or the
    # owner supplied): still no command string.
    assert set(kinds) == {
        "uci_equals",
        "probe",
        "config_has",
        "ping",
        "client_dns",
        "client_dhcp",
        "client_internet",
        "client_blocked",
        "client_reaches",
    }
    assert set({"kind": "client_dns", "zone": "guest"}) == {"kind", "zone"}


# ---- the mechanical disagreement flag ---------------------------------------

DIFF = "firewall.fwd_8443=redirect\nfirewall.fwd_8443.dest_port='8443'"
SECTIONS = ["firewall fwd_8443 redirect fwd_8443"]


def flags(steps, diff=DIFF, sections=SECTIONS):
    return ex.disagreements(steps, diff, sections)


def test_no_flag_when_steps_name_exactly_what_is_touched():
    assert flags(["Create firewall.fwd_8443 as a redirect", "Set its port"]) == []


def test_flag_when_a_step_names_a_section_not_touched():
    out = flags(["Create firewall.fwd_8443", "Also edit firewall.allow_ssh"])
    assert any("firewall.allow_ssh" in line and "not in Newton's touched list" in line for line in out)


def test_flag_when_a_touched_section_is_named_by_no_step():
    out = flags(["Open the printer port", "Done"])
    assert any("firewall.fwd_8443" in line and "no step mentions" in line for line in out)


def test_section_name_alone_counts_as_a_mention():
    assert flags(["Add the fwd_8443 redirect", "Set its port"]) == []


def test_prose_with_dots_and_unknown_packages_is_not_a_path():
    assert flags(["Create firewall.fwd_8443 (see e.g. example.com)", "v1.2 note"]) == []


def test_anonymous_section_refs_match_by_index():
    diff = "firewall.@rule[3].target='DROP'"
    assert ex.disagreements(["Drop traffic with firewall.@rule[3]"], diff, []) == []
    # a negative index cannot be resolved by a reader, so it matches the type
    assert ex.disagreements(["Drop traffic with firewall.@rule[-1]"], diff, []) == []
    # a wrong index is no longer waved through by type
    out = ex.disagreements(["Drop traffic with firewall.@rule[0]"], diff, [])
    assert any("firewall.@rule[0]" in line and "not in Newton's touched list" in line for line in out)
    out = ex.disagreements(["Drop traffic with firewall.@zone[0]"], diff, [])
    assert any("firewall.@zone[0]" in line for line in out)


def test_an_honest_step_that_describes_an_anonymous_section_in_words_is_not_a_disagreement():
    diff = "system.@system[0].description='hello'"
    check = ex.mechanical_check(["Set the system description"], diff, [])
    assert check.disagreements == []
    assert check.also_touches == ["system.@system[0]"]
    assert ex.disagreements(["Set the system description"], diff, []) == []


def test_a_named_section_no_step_mentions_is_still_a_disagreement_not_an_also_touches():
    check = ex.mechanical_check(["Open the printer port", "Done"], DIFF, SECTIONS)
    assert any("no step mentions" in line for line in check.disagreements)
    assert check.also_touches == []


def test_a_step_that_names_the_anonymous_section_is_not_listed_as_also_touched():
    diff = "system.@system[0].description='hello'"
    check = ex.mechanical_check(["Set system.@system[0] description"], diff, [])
    assert check.disagreements == [] and check.also_touches == []


def test_unparsed_diff_lines_are_counted_not_waved_through():
    check = ex.mechanical_check(["Change the firewall"], 'firewall."weird".x=1\n', [])
    assert check.disagreements == [] and check.unparsed == 1
    check = ex.mechanical_check(["Create firewall.fwd_8443", "Set its port"], DIFF + "\n\n?junk line\n", SECTIONS)
    assert check.unparsed == 1
    assert ex.mechanical_check(["Create firewall.fwd_8443", "Set its port"], DIFF, SECTIONS).unparsed == 0


def test_a_dropped_placeholder_comment_counts_as_a_change_line():
    batch = "# dropped placeholder: set wireless.x.key=<redacted:aaaaaaaa>\nset a.b=c\n# plain comment"
    assert ex.change_lines(batch) == 2


@pytest.mark.parametrize("bad", [
    "hangul\u3164filler", "hangul\u115fchoseong", "jungseong\u1160x", "halfwidth\uffa0x",
    "braille\u2800blank", "zwj\u200dx", "lsep\u2028x", "psep\u2029x", "ideographic\u3000space",
    "private\ue000use", "unassigned\u0378x", "tag\U000e0041x", "ogham\u1680space",
])
def test_blank_looking_invisible_characters_are_refused(bad):
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(intent=bad), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(steps=[bad, "ok"]), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(risk=f"fine\n{bad}"), change_lines=2)


def test_invisible_characters_in_claim_fields_are_refused():
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(
            good(expect=[{"kind": "uci_equals", "path": "dhcp.a.name", "equals": "x\u3164y"}]),
            change_lines=2,
        )
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(
            good(expect=[{"kind": "probe", "probe": ["iface-absent", "gu\u2800est"]}]), change_lines=2
        )


def test_flag_output_is_plain_ascii_safe_text():
    out = flags(["Edit firewall.evil", "x"])
    assert all(line.isprintable() for line in out)


@pytest.mark.parametrize("bad", [
    "khmer឴x", "khmer឵x", "cgj͏x", "vs16️x", "vs1︀x", "objrepl￼x",
    "vs17\U000e0100x", "vs256\U000e01efx", "mongolian᠋x", "mongolian᠎x", "ZWNBSP﻿x",
])
def test_more_invisible_characters_are_refused(bad):
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(intent=bad), change_lines=2)
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(good(steps=[bad, "ok"]), change_lines=2)


# ---- the vendor claims (config_has and ping) -------------------------------

VENDOR = "vyos"
V_LINE = "set interfaces ethernet eth0 mtu 1500"
C_CONFIG = {"kind": "config_has", "line": V_LINE}
C_PING = {"kind": "ping", "host": "192.0.2.10"}


def vendor_explanation(**overrides):
    """An explanation whose claims are the vendor ones (platform vyos)."""
    return make_explanation(BATCH, **overrides)


def test_the_vendor_claims_are_accepted_on_a_vendor_platform():
    out = ex.parse_explanation(
        vendor_explanation(expect=[C_CONFIG, C_PING]),
        change_lines=2,
        platform=VENDOR,
    )
    assert out["expect"] == [C_CONFIG, C_PING]
    assert ex.claim_to_probe(out["expect"][0]) == ["config_has", V_LINE]
    assert ex.claim_to_probe(out["expect"][1]) == ["ping", "192.0.2.10"]


def test_the_config_has_probe_carries_the_canonical_vendor_line():
    """The line is re-rendered from the tokens, never copied from the agent."""
    claim = {"kind": "config_has", "line": "set system description 'hello world'"}
    out = ex.parse_explanation(
        vendor_explanation(expect=[claim]), change_lines=2, platform=VENDOR
    )
    assert out["expect"][0]["line"] == "set system description 'hello world'"
    assert ex.claim_to_probe(out["expect"][0]) == [
        "config_has",
        "set system description 'hello world'",
    ]
    # a value the agent quoted but that needs no quotes comes back canonical
    claim = {"kind": "config_has", "line": "set system description 'hello'"}
    out = ex.parse_explanation(
        vendor_explanation(expect=[claim]), change_lines=2, platform=VENDOR
    )
    assert ex.claim_to_probe(out["expect"][0]) == ["config_has", "set system description hello"]


def test_a_config_has_line_of_300_characters_is_accepted():
    line = "set x" + "a" * 295
    assert len(line) == 300
    out = ex.parse_explanation(
        vendor_explanation(expect=[{"kind": "config_has", "line": line}]),
        change_lines=2,
        platform=VENDOR,
    )
    assert out["expect"][0]["line"] == line


@pytest.mark.parametrize("line", [
    "show version",                                 # a verb the vendor does not take
    "delete interfaces ethernet eth0",              # not a set statement
    'set system description "hello"',               # a double quote
    "set system description 'caf\u00e9'",           # not ASCII
    "set x" + "a" * 296,                            # 301 characters
    "set vpn ipsec pre-shared-key=abc",             # looks like it carries a secret
    "set interfaces ethernet eth0; reboot",         # a metacharacter
    "set interfaces ethernet eth0 | tee /tmp/x",    # a pipe
    "# a comment",                                  # not a statement
    "",                                             # empty
    "   ",                                          # blank
    "set interfaces ethernet eth0\nset a b c",       # two statements
])
def test_a_bad_config_has_claim_is_refused(line):
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(
            vendor_explanation(expect=[{"kind": "config_has", "line": line}]),
            change_lines=2,
            platform=VENDOR,
        )


@pytest.mark.parametrize("host", [
    "192.0.2.1 extra",     # a space
    "",                    # empty
    "192.0.2.1; reboot",   # a metacharacter
    "192.0.2.1\n",         # a control character
    "a" * 254,             # too long
])
def test_a_bad_ping_host_is_refused(host):
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(
            vendor_explanation(expect=[{"kind": "ping", "host": host}]),
            change_lines=2,
            platform=VENDOR,
        )


def test_openwrt_refuses_the_vendor_claims():
    for claim in (C_CONFIG, C_PING):
        with pytest.raises(ex.ExplanationError) as err:
            ex.parse_explanation(good(expect=[claim]), change_lines=2)
        assert claim["kind"] in str(err.value)
        assert "openwrt" in str(err.value)


def test_a_vendor_platform_refuses_the_openwrt_claims():
    for claim in (
        {"kind": "uci_equals", "path": "firewall.fwd_8443.dest_port", "equals": "8443"},
        {"kind": "probe", "probe": ["iface-absent", "guestx"]},
    ):
        with pytest.raises(ex.ExplanationError) as err:
            ex.parse_explanation(good(expect=[claim]), change_lines=2, platform=VENDOR)
        assert claim["kind"] in str(err.value)
        assert VENDOR in str(err.value)


def test_the_default_platform_is_openwrt():
    """No platform argument means the OpenWrt claim kinds, as before."""
    claim = {"kind": "uci_equals", "path": "firewall.fwd_8443.dest_port", "equals": "8443"}
    out = ex.parse_explanation(good(expect=[claim]), change_lines=2)
    assert out["expect"] == [claim]


def test_the_vendor_claims_are_described_in_plain_words():
    assert ex.describe_claim(C_CONFIG) == f"config has {V_LINE}"
    assert ex.describe_claim(C_PING) == "ping 192.0.2.10"
    assert ex.describe_failed_claim(C_CONFIG, "absent") == f"config line not present: {V_LINE}"
    assert ex.describe_failed_claim(C_PING, "absent") == "ping 192.0.2.10: no answer"


def test_the_failed_config_has_text_is_cut_to_80_characters():
    line = "set system description " + "a" * 200
    text = ex.describe_failed_claim({"kind": "config_has", "line": line}, "absent")
    shown = text.split("config line not present: ", 1)[1]
    assert len(shown) == 80
    assert text.startswith("config line not present: ")


def test_the_refusal_never_echoes_the_agent_text():
    marker = "ZZ-MARKER"
    for line in (f"show {marker}", f"delete {marker}", f"set {marker}; reboot"):
        with pytest.raises(ex.ExplanationError) as err:
            ex.parse_explanation(
                vendor_explanation(expect=[{"kind": "config_has", "line": line}]),
                change_lines=2,
                platform=VENDOR,
            )
        assert marker not in str(err.value)


def test_the_vendor_claim_kinds_carry_no_command():
    """A vendor claim is a statement or a host name, never a command to run."""
    assert set(ex.ConfigHasClaim.model_fields) == {"kind", "line"}
    assert set(ex.PingClaim.model_fields) == {"kind", "host"}
    for model in (ex.ConfigHasClaim, ex.PingClaim):
        assert model.model_config["extra"] == "forbid"
        assert model.model_config["strict"] is True
        assert model.model_config["frozen"] is True


# ---- review fixes ------------


def test_a_platform_without_a_tokenizer_carries_no_claim_kinds():
    """Only the platforms with a tokenizer carry the vendor claims.

    The vendor claims are checked with the tokenizer of the platform they
    are for, so a claim on a platform with no tokenizer of its own would
    be checked against the wrong grammar.  Such a platform carries no
    claim kinds at all.

    The CHR is the exception: it carries the ping claim only
   , because its export normalises its own lines.
    A Junos carries the two vendor claims: it has a tokenizer
    of its own, and its display-set output can be compared with a line.
    """
    claims = (
        C_CONFIG,
        C_PING,
        {"kind": "uci_equals", "path": "firewall.fwd_8443.dest_port", "equals": "8443"},
        {"kind": "probe", "probe": ["iface-absent", "guestx"]},
    )
    for platform in ("eos", "fortios", "vyos2"):
        for claim in claims:
            with pytest.raises(ex.ExplanationError) as err:
                ex.parse_explanation(good(expect=[claim]), change_lines=2, platform=platform)
            assert claim["kind"] in str(err.value), (platform, claim)


def test_the_allow_list_pins_the_platforms_that_carry_claims():
    """The claim kinds come from an explicit allow-list."""
    assert ex.CLAIM_KINDS_BY_PLATFORM["openwrt"] == (
        "uci_equals", "probe", "client_dns", "client_dhcp", "client_internet",
        "client_blocked", "client_reaches",
    )
    assert ex.CLAIM_KINDS_BY_PLATFORM["vyos"] == ("config_has", "ping")
    assert ex.CLAIM_KINDS_BY_PLATFORM["routeros"] == ("ping",)
    assert ex.CLAIM_KINDS_BY_PLATFORM["junos"] == ("config_has", "ping")
    assert set(ex.CLAIM_KINDS_BY_PLATFORM) == {
        "openwrt", "vyos", "routeros", "junos",
    }


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",       # the loopback range
        "127.0.0.53",
        "127.255.255.254",
        "0.0.0.0",         # the unspecified address
        "::1",             # the IPv6 loopback
    ],
)
def test_a_ping_claim_to_a_vacuous_address_is_refused(host):
    """A ping the device answers itself cannot fail, so it is refused."""
    with pytest.raises(ex.ExplanationError):
        ex.parse_explanation(
            vendor_explanation(expect=[{"kind": "ping", "host": host}]),
            change_lines=2,
            platform=VENDOR,
        )


@pytest.mark.parametrize("host", ["192.0.2.10", "203.0.113.7", "peer.example"])
def test_a_ping_claim_to_a_routable_host_is_accepted(host):
    """An ordinary peer is still a fine ping claim."""
    out = ex.parse_explanation(
        vendor_explanation(expect=[{"kind": "ping", "host": host}]),
        change_lines=2,
        platform=VENDOR,
    )
    assert out["expect"] == [{"kind": "ping", "host": host}]


def test_the_canonical_claim_line_is_the_sealed_text():
    """The canonical line is what the sealed probe carries."""
    claim = {"kind": "config_has", "line": "set system description 'hello'"}
    out = ex.parse_explanation(
        vendor_explanation(expect=[claim]), change_lines=2, platform=VENDOR
    )
    assert ex.canonical_claim_line(out["expect"][0]["line"]) == (
        "set system description hello"
    )
    assert ex.claim_to_probe(out["expect"][0]) == [
        "config_has",
        "set system description hello",
    ]
