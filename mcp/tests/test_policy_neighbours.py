"""Round-p neighbour tests for the two planted-defect gaps.

Gap 1 (firewall-type check in policy.py's section-type elif dispatch): for EVERY firewall section type
(design 5.2 `firewall-type` row) a lab-profile change of that type that the
design says needs no approval must stay free and must NOT raise
`firewall-type`; removing that type from the dispatch (the planted defect removed
"redirect") makes the benign neighbour fall into the unknown-type branch and
these tests go red.  `include` is the exception: any change to it fires
(`exec-include`), never `firewall-type`.

Gap 2 (PATH_PREFIX_EXEMPT_RE): the prefix exemption is exactly
`^[0-9A-Fa-f.:]+/[0-9]{1,3}$` -- widening the digit run (the planted defect
went to four digits) turned nothing red.  These tests pin the boundary of all
three 5.2 path-option exemptions (prefix, rate, URL) and that an unexempt '/'
fires on set, add_list and a deleted committed value.

The helper shapes mirror mcp/tests/test_policy_hardening.py.
"""

import pytest

from newton_mcp.policy import classify
from newton_mcp.server import Device


def dev(profile="lab", mgmt_interface="lan", mgmt_zone="lan", wan_zones=("wan",)):
    return Device("quasar", "openwrt", "192.0.2.1", "root",
                  profile=profile, mgmt_interface=mgmt_interface, mgmt_zone=mgmt_zone,
                  wan_zones=wan_zones)


def decide(diff, batch="", device=None, section_facts=None, deleted_values=None):
    kwargs = {}
    if deleted_values is not None:
        kwargs["deleted_values"] = deleted_values
    return classify(device if device is not None else dev(), batch, diff,
                    section_facts=section_facts, **kwargs)


def free(diff, batch="", device=None, section_facts=None, deleted_values=None):
    return decide(diff, batch, device, section_facts, deleted_values) == {"requires_approval": False, "risk": "low", "reasons": []}


def fires(diff, code, device=None, section_facts=None, deleted_values=None):
    result = decide(diff, device=device, section_facts=section_facts,
                    deleted_values=deleted_values)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any(reason.startswith(code + ":") for reason in result["reasons"]), result["reasons"]
    return result


def no_firewall_type(diff, device=None, section_facts=None):
    result = decide(diff, device=device, section_facts=section_facts)
    assert not any(reason.startswith("firewall-type:") for reason in result["reasons"]), result["reasons"]
    return result


# ---- gap 1: one benign neighbour per allowed firewall section type ----


def test_neighbour_defaults_synflood_protect_is_free_and_not_firewall_type():
    # design 5.2 `defaults-accept` fires only on input/forward -> ACCEPT;
    # synflood_protect is a tightening that needs no approval
    facts = {("firewall", "@defaults[0]"): ("defaults", None)}
    assert free("firewall.@defaults[0].synflood_protect='1'", section_facts=facts)
    no_firewall_type("firewall.@defaults[0].synflood_protect='1'", section_facts=facts)


def test_neighbour_zone_tightening_is_free_and_not_firewall_type():
    # an identified non-mgmt non-wan zone setting input to DROP is a tightening
    facts = {("firewall", "@zone[2]"): ("zone", "guest")}
    assert free("firewall.@zone[2].input='DROP'", section_facts=facts)
    no_firewall_type("firewall.@zone[2].input='DROP'", section_facts=facts)


def test_neighbour_forwarding_lan_to_guest_is_free_and_not_firewall_type():
    # a forwarding between two non-wan zones that are not the mgmt zone
    # (mgmt_zone 'core' here; with the default mgmt zone 'lan' this forwarding
    # would correctly fire forwarding-mgmt)
    device = dev(mgmt_zone="core")
    diff = "firewall.f=forwarding\nfirewall.f.src='lan'\nfirewall.f.dest='guest'"
    assert free(diff, device=device)
    no_firewall_type(diff, device=device)
    facts = {("firewall", "@forwarding[0]"): ("forwarding", None)}
    anon = "firewall.@forwarding[0].src='lan'\nfirewall.@forwarding[0].dest='guest'"
    assert free(anon, device=device, section_facts=facts)
    no_firewall_type(anon, device=device, section_facts=facts)


def test_neighbour_redirect_from_a_non_wan_zone_is_free_and_not_firewall_type():
    # design 5.2 `wan-redirect` fires only from a wan zone or '*'; a redirect
    # whose src the diff shows to be a non-wan zone is free.  This is the
    # neighbour that goes red when "redirect" is dropped from
    # the firewall-type elif dispatch in policy.py (the section would become `firewall-type`).
    diff = "firewall.r2=redirect\nfirewall.r2.src='guest'\nfirewall.r2.dest='lan'"
    assert free(diff)
    no_firewall_type(diff)
    facts = {("firewall", "@redirect[0]"): ("redirect", None)}
    anon = "firewall.@redirect[0].src='guest'\nfirewall.@redirect[0].dest_ip='192.0.2.5'"
    assert free(anon, section_facts=facts)
    no_firewall_type(anon, section_facts=facts)


def test_neighbour_lan_rule_with_reject_target_is_free_and_not_firewall_type():
    # design 5.2 `wan-rule` needs src from the wan list; a lan rule with a
    # REJECT target is a tightening
    diff = "firewall.lr=rule\nfirewall.lr.src='lan'\nfirewall.lr.target='REJECT'"
    assert free(diff)
    no_firewall_type(diff)
    facts = {("firewall", "@rule[0]"): ("rule", None)}
    anon = "firewall.@rule[0].src='lan'\nfirewall.@rule[0].target='REJECT'"
    assert free(anon, section_facts=facts)
    no_firewall_type(anon, section_facts=facts)


def test_include_always_fires_exec_include_and_never_firewall_type():
    # design 5.2: ANY change to an include section fires (exec-include);
    # it is an allowed type, so the reason is never firewall-type
    result = fires("firewall.i2=include", "exec-include")
    assert not any(reason.startswith("firewall-type:") for reason in result["reasons"])
    facts = {("firewall", "@include[0]"): ("include", None)}
    result = fires("firewall.@include[0].enabled='0'", "exec-include", section_facts=facts)
    assert not any(reason.startswith("firewall-type:") for reason in result["reasons"])


@pytest.mark.parametrize("section_type", ["nat", "ipset"])
def test_unknown_firewall_type_fires_on_a_new_named_section(section_type):
    fires(f"firewall.newsec={section_type}\nfirewall.newsec.name='x'", "firewall-type")


@pytest.mark.parametrize("section_type", ["nat", "ipset"])
def test_unknown_firewall_type_fires_through_a_router_fact(section_type):
    # the type comes from the section fact, not from the diff
    fires("firewall.mysec.name='x'", "firewall-type",
          section_facts={("firewall", "mysec"): (section_type, None)})


@pytest.mark.parametrize("section_type", ["nat", "ipset"])
def test_unknown_firewall_type_fires_on_an_anonymous_selector(section_type):
    fires(f"firewall.@{section_type}[0].name='x'", "firewall-type")


# ---- gap 2: the path-option exemption boundaries ----


def path_diff(value):
    return f"dhcp.@dnsmasq[0].foo='{value}'"


@pytest.mark.parametrize("value", [
    "10.0.0.0/8",        # 1 digit
    "fe80::/10",         # IPv6 prefix
    "::/0",              # the everything prefix
    "192.168.0.0/255",   # 3 digits: the top of the allowed run
])
def test_path_prefix_exemption_boundaries(value):
    assert free(path_diff(value))


@pytest.mark.parametrize("value", [
    "10.0.0.0/1234",     # 4 digits: widening {1,3} to {1,4} must stay red
    "10.0.0.0/",         # no digit run at all
    "/8",                # no address before the slash
    "10.0.0.0/8/9",      # a second slash is a path, not a prefix
    "10.0.0.0/a",        # letters are not a prefix length
])
def test_path_prefix_non_exemptions_fire(value):
    fires(path_diff(value), "path-option")


@pytest.mark.parametrize("value", ["10/second", "10/minute", "10/hour", "10/day"])
def test_path_rate_exemption(value):
    assert free(path_diff(value))


@pytest.mark.parametrize("value", [
    "10/minutes",        # trailing 's': not one of the four units
    "10/fortnight",      # no such unit
    "ten/minute",        # the count must be digits
])
def test_path_rate_non_exemptions_fire(value):
    fires(path_diff(value), "path-option")


@pytest.mark.parametrize("value", ["http://x", "https://x"])
def test_path_url_exemption(value):
    assert free(path_diff(value))


@pytest.mark.parametrize("value", [
    "file:///etc/passwd",   # design 5.2: only http(s)://, never file://
    "ftp://x",
    "ssh://x",
    "httpx://x",            # the scheme must be exactly http or https
    "http:/x",              # one slash is not a URL
])
def test_path_url_non_exemptions_fire(value):
    fires(path_diff(value), "path-option")


def test_unexempt_slash_fires_on_set_add_list_and_deleted_value():
    fires("system.@system[0].description='a/b'", "path-option")
    fires("dhcp.lan.dhcp_option+='/x'", "path-option")
    fires("-dhcp.lan.dhcp_option", "path-option")


# ---- an undo can supply the committed deleted-option values ----


def test_deleted_plain_option_is_free_when_the_committed_value_has_no_path():
    values = {("dhcp", "lan", "dhcp_option"): "6,192.0.2.1"}
    assert free("-dhcp.lan.dhcp_option", deleted_values=values)


def test_deleted_option_with_a_path_in_the_committed_value_fires():
    values = {("system", "main", "description"): "a/b"}
    fires("-system.main.description", "path-option", deleted_values=values)


def test_deleted_list_option_with_a_path_in_any_item_fires():
    values = {("dhcp", "lan", "dhcp_option"): ("6,1.2.3.4", "/x")}
    fires("-dhcp.lan.dhcp_option", "path-option", deleted_values=values)


def test_deleted_option_missing_from_committed_values_stays_fail_safe():
    values = {("dhcp", "lan", "other"): "6,192.0.2.1"}
    fires("-dhcp.lan.dhcp_option", "path-option", deleted_values=values)


def test_deleted_option_without_committed_values_stays_fail_safe():
    fires("-dhcp.lan.dhcp_option", "path-option")


def test_deleted_section_stays_fail_safe_even_when_its_values_are_known():
    values = {("dhcp", "lan", "dhcp_option"): "6,192.0.2.1"}
    fires("-dhcp.lan", "path-option", deleted_values=values)
