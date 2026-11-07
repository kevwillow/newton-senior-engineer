"""R2 review hardening for the host policy (newton_mcp.policy).

(a) R2-POL-01: the host fires ``mgmt-interface`` whenever the router's
    section fact identifies the management interface, even when the diff's
    section token does not.  Today the fact silences the fire for an
    anonymous section.
(b) R2-POL-02: the identifier regexes are bounded to the design 3.3 caps
    so an over-cap identifier (e.g. 100 KB) is ``unparsed-change`` instead
    of being silently accepted.
"""

from __future__ import annotations

import pytest

from newton_mcp import policy
from newton_mcp.policy import classify
from newton_mcp.server import Device


# ---- shared helpers --------------------------------------------------------


def dev(mgmt_interface="lan"):
    return Device("quasar", "openwrt", "192.0.2.1", "root",
                  profile="lab", mgmt_interface=mgmt_interface)


def decide(diff, *, device=None, section_facts=None):
    return classify(device if device is not None else dev(), "set a.b.c=1", diff,
                    section_facts=section_facts)


def fires(diff, code, *, device=None, section_facts=None):
    result = decide(diff, device=device, section_facts=section_facts)
    assert result["requires_approval"] is True, result
    assert any(reason.startswith(code + ":") for reason in result["reasons"]), result["reasons"]
    return result


def free(diff, *, device=None, section_facts=None):
    result = decide(diff, device=device, section_facts=section_facts)
    assert result == {"requires_approval": False, "risk": "low", "reasons": []}, result


# ---- R2-POL-01: mgmt-interface fires from the router fact ---------------------


def test_mgmt_interface_fires_when_fact_names_the_mgmt_interface_for_an_anon_section():
    """A network.@interface[N] the diff cannot name whose router fact is
    (interface, mgmt_interface) is the mgmt interface (R2-POL-01)."""
    fires(
        "network.@interface[2].ipaddr='10.9.9.1'",
        "mgmt-interface",
        section_facts={("network", "@interface[2]"): ("interface", "lan")},
    )


def test_mgmt_interface_fires_with_a_custom_mgmt_name_through_fact():
    """The same fire works for a device whose mgmt_interface is not 'lan'."""
    fires(
        "network.@interface[3].proto='static'",
        "mgmt-interface",
        device=dev(mgmt_interface="mgmt0"),
        section_facts={("network", "@interface[3]"): ("interface", "mgmt0")},
    )


def test_mgmt_interface_does_not_fire_when_fact_names_a_different_interface():
    """A section whose fact says name='guest' is not the mgmt interface."""
    free(
        "network.@interface[4].ipaddr='10.9.9.1'",
        section_facts={("network", "@interface[4]"): ("interface", "guest")},
    )


def test_mgmt_interface_fires_for_named_section_with_fact_named_mgmt():
    """A named section 'lan' whose router fact agrees also fires; today
    it fires anyway through named_mgmt, this test pins the new code path."""
    fires(
        "network.lan.ipaddr='10.9.9.1'",
        "mgmt-interface",
        section_facts={("network", "lan"): ("interface", "lan")},
    )


def test_mgmt_interface_fires_when_fact_is_none_none_and_section_token_is_mgmt():
    """When the router looked at both views and found nothing (fact is
    (None, None)) but the diff names the section like the mgmt interface,
    it is the mgmt interface (R2-POL-01)."""
    fires(
        "network.lan.proto='static'",
        "mgmt-interface",
        section_facts={("network", "lan"): (None, None)},
    )


def test_section_unidentified_fires_for_fact_none_none_with_non_mgmt_name():
    """When the fact is (None, None) and the section token is not the mgmt
    interface, the existing section-unidentified fire still wins."""
    fires(
        "network.guest.proto='static'",
        "section-unidentified",
        section_facts={("network", "guest"): (None, None)},
    )


def test_section_unidentified_fires_for_anon_section_with_fact_none_none():
    """When the fact is (None, None) and the section is anonymous, we still
    don't know what it is."""
    fires(
        "network.@interface[2].ipaddr='10.9.9.1'",
        "section-unidentified",
        section_facts={("network", "@interface[2]"): (None, None)},
    )


# ---- R2-POL-02: regex caps (design 3.3) --------------------------------------


def _check_caps(pattern, *, accept, refuse):
    """Both the accept and the refuse cases must move the same way."""
    for value in accept:
        assert pattern.fullmatch(value), f"{value!r} should be accepted"
    for value in refuse:
        assert not pattern.fullmatch(value), f"{value!r} should be refused"


def test_config_name_regex_is_capped_at_32():
    _check_caps(
        policy.CONFIG_NAME_RE,
        accept=["a", "network", "a" * 32],
        refuse=["", "A", "a" * 33, "a" * 100_000],
    )


def test_section_name_regex_is_capped_at_64():
    _check_caps(
        policy.SECTION_NAME_RE,
        accept=["lan", "a" * 64, "x" * 64],
        refuse=["", "a" * 65, "a" * 100_000, "a.b"],
    )


def test_anon_section_regex_is_capped_at_32_type_and_3_digits():
    _check_caps(
        policy.ANON_SECTION_RE,
        accept=["@interface[0]", "@a[1]", "@" + "a" * 32 + "[999]"],
        refuse=[
            "",
            "interface[0]",          # no leading @
            "@interface[]",          # missing index
            "@" + "a" * 33 + "[1]",  # type too long
            "@interface[1000]",      # 4 digits
            "@interface[-1]",        # negative not allowed
            "@interface[1",
            "interface[1]",
        ],
    )


def test_option_name_regex_is_capped_at_64():
    _check_caps(
        policy.OPTION_NAME_RE,
        accept=["key", "a" * 64],
        refuse=["", "a" * 65, "a" * 100_000, "a-b", "a.b"],
    )


def test_section_type_regex_is_capped_at_64():
    _check_caps(
        policy.SECTION_TYPE_RE,
        accept=["zone", "a" * 64],
        refuse=["", "a" * 65, "a" * 100_000],
    )


def test_identifier_regex_is_capped_at_64():
    _check_caps(
        policy.IDENTIFIER_RE,
        accept=["lan", "a" * 64],
        refuse=["", "a" * 65, "a" * 100_000],
    )


@pytest.mark.parametrize("identifier", [
    "a" * 33,            # one over the 32-char config cap
    "a" * 65,            # one over the 64-char section name cap
    "a" * 65 + ".x='y'",  # one over the 64-char option cap
])
def test_over_cap_identifier_in_a_diff_line_fires_unparsed_change(identifier):
    """A 100KB identifier in the diff is an unparsed change."""
    diff = f"{identifier}.proto='static'" if "." not in identifier else identifier
    result = decide(diff)
    assert result["requires_approval"] is True, result
    assert any("unparsed-change" in r for r in result["reasons"]), result["reasons"]


def test_at_cap_identifier_in_a_diff_line_is_accepted():
    """An identifier exactly at the cap (config 32, section 64, option 64)
    parses and is free on lab."""
    diff = "network." + "a" * 64 + "='b'"
    free(diff)


def test_at_cap_anon_section_in_a_diff_line_is_accepted():
    """An @interface[N] at the cap (32-char type, 3-digit N) parses."""
    diff = "network.@" + "a" * 32 + "[999].proto='static'"
    free(diff)