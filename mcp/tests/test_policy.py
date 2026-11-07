"""Tests for newton_mcp.policy: profiles (K5) and the leash (K6).

The round-1 tests of approval_for_batch / approval_for_diff moved here: the
same inputs now go through classify(), with 'prod' preserving the old
"requires approval" guarantees and 'lab' showing what the profiles free.
"""

from pathlib import Path

import pytest

from newton_mcp import policy
from newton_mcp.server import Device, parse_plan


def dev(profile="lab", mgmt_interface="lan", mgmt_zone="lan"):
    return Device("quasar", "openwrt", "192.0.2.1", "root",
                  profile=profile, mgmt_interface=mgmt_interface, mgmt_zone=mgmt_zone)


def decide(diff, batch="", device=None):
    return policy.classify(device if device is not None else dev(), batch, diff)


def free(diff, batch="", device=None):
    return decide(diff, batch, device) == {"requires_approval": False, "risk": "low", "reasons": []}


# ---- profiles (spec item 8) ----


def test_missing_profile_means_prod_and_requires_approval_for_a_cosmetic_change():
    device = Device("quasar", "openwrt", "192.0.2.1", "root")   # no profile set anywhere
    assert device.profile == "prod"
    result = policy.classify(device, "set system.@system[0].description='x'",
                             "system.@system[0].description='x'")
    assert result["requires_approval"] is True
    assert result["reasons"] == ["profile 'prod': every write requires approval"]
    assert result["risk"] == "low"


def test_invalid_profile_is_an_inventory_error_not_prod():
    with pytest.raises(ValueError, match="profile must be 'lab' or 'prod'"):
        decide("dhcp.lan.start='50'", device=dev(profile="staging"))


def test_lab_cosmetic_change_requires_no_approval():
    assert free("dhcp.lan.start='50'", "set dhcp.lan.start='50'")
    assert free("system.@system[0].description='lab router'", "set system.@system[0].description='lab router'")


def test_empty_batch_and_diff_need_nothing_on_either_profile():
    assert free("")
    assert decide("", device=dev(profile="prod")) == {"requires_approval": False, "risk": "low", "reasons": []}


def test_leash_requires_approval_on_every_profile():
    for device in (dev(profile="lab"), dev(profile="prod")):
        result = policy.classify(device, "set dropbear.@dropbear[0].PasswordAuth='on'",
                                 "dropbear.@dropbear[0].PasswordAuth='on'")
        assert result["requires_approval"] is True
        assert result["risk"] == "critical"


# ---- leash: management access services ----


@pytest.mark.parametrize("config, diff_line", [
    ("dropbear", "dropbear.@dropbear[0].PasswordAuth='on'"),
    ("dropbear", "-dropbear.@dropbear[0].RootPasswordAuth"),
    ("rpcd", "rpcd.@login[0].password='$p$root'"),
    ("uhttpd", "uhttpd.main.listen_http='0.0.0.0:80'"),
    ("uhttpd", "+uhttpd.main.listen_http='[::]:80'"),
])
def test_lab_change_to_management_service_requires_approval(config, diff_line):
    result = decide(diff_line, f"set {diff_line.split(' ', 1)[0]}" if " " in diff_line else f"set {diff_line}")
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any(config in reason and "management access service" in reason for reason in result["reasons"])


# ---- leash: management interface ----


@pytest.mark.parametrize("diff", [
    "network.lan.ipaddr='10.9.9.1'",
    "network.lan.proto='static'",
    "network.lan=interface",
    "-network.lan",
    "network.@interface[0].ipaddr='10.9.9.1'",
    "-network.@interface[2]",
])
def test_lab_mgmt_interface_change_requires_approval(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("management interface" in reason for reason in result["reasons"])


def test_lab_mgmt_interface_change_with_custom_name_requires_approval():
    device = dev(mgmt_interface="mgmt0")
    assert free("network.lan.ipaddr='10.9.9.1'", device=device)
    result = decide("network.mgmt0.ipaddr='10.109.0.11'", device=device)
    assert result["requires_approval"] is True
    assert any("management interface 'mgmt0'" in reason for reason in result["reasons"])


def test_lab_non_mgmt_interface_change_requires_no_approval():
    assert free("network.wan.proto='pppoe'", "set network.wan.proto='pppoe'")
    assert free("network.guest.ipaddr='192.168.30.1'", "set network.guest.ipaddr='192.168.30.1'")
    # an @device[N] section is bridge membership, which is now a leash
    # operation. This line used to assert "free"; the stricter expectation is
    # deliberate (review finding F6); the two lines above still hold.
    result = decide("network.@device[0].name='br-guest'", "set network.@device[0].name='br-guest'")
    assert result["requires_approval"] is True
    assert any("bridge/VLAN membership" in reason for reason in result["reasons"])


# ---- leash: management zone and forwardings ----


@pytest.mark.parametrize("diff", [
    "firewall.lan2=zone\nfirewall.lan2.name='lan'\nfirewall.lan2.input='REJECT'",
    "firewall.@zone[0].input='REJECT'",        # unidentified zone: may be the mgmt zone (ow-fw shapes)
    "firewall.@zone[1].input='DROP'",
    "firewall.@zone[0].network+='eth9'",
    "+firewall.@zone[0].network='eth9'",
    "firewall.@zone[0].name='lan2'",
    "-firewall.@zone[0]",
    "firewall.@forwarding[1].dest='lan'",
    "firewall.wan_lan=forwarding\nfirewall.wan_lan.src='wan'\nfirewall.wan_lan.dest='lan'",
])
def test_lab_mgmt_zone_change_requires_approval(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("management zone" in reason for reason in result["reasons"])


def test_lab_mgmt_zone_with_custom_name_requires_approval():
    device = dev(mgmt_zone="core")
    # design 5.2 wan-forwarding: a forwarding FROM a wan zone fires now,
    # even when the management zone ('core') is not involved
    result = decide("firewall.g=forwarding\nfirewall.g.src='wan'\nfirewall.g.dest='lan'", device=device)
    assert result["requires_approval"] is True
    assert any("wan-forwarding" in reason for reason in result["reasons"])
    assert free("firewall.g=forwarding\nfirewall.g.src='guest'\nfirewall.g.dest='wan'", device=device)
    result = decide("firewall.g=forwarding\nfirewall.g.src='guest'\nfirewall.g.dest='core'", device=device)
    assert result["requires_approval"] is True
    assert any("management zone 'core'" in reason for reason in result["reasons"])


def test_lab_new_zone_named_after_a_custom_mgmt_zone_requires_approval():
    device = dev(mgmt_zone="core")
    result = decide("firewall.z=zone\nfirewall.z.name='core'\nfirewall.z.input='REJECT'", device=device)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("management zone 'core'" in reason for reason in result["reasons"])


def test_lab_new_zone_named_lan_is_free_when_the_mgmt_zone_is_not_lan():
    device = dev(mgmt_zone="core")
    assert free("firewall.z=zone\nfirewall.z.name='lan'\nfirewall.z.input='REJECT'\nfirewall.z.forward='REJECT'", device=device)


def test_lab_new_zone_named_lan_requires_approval_with_default_mgmt_zone():
    result = decide("firewall.z=zone\nfirewall.z.name='lan'\nfirewall.z.input='REJECT'")
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("management zone 'lan'" in reason for reason in result["reasons"])


def test_lab_new_zone_with_an_unrelated_name_is_free_with_default_mgmt_zone():
    assert free("firewall.z=zone\nfirewall.z.name='guest'\nfirewall.z.input='REJECT'\nfirewall.z.forward='REJECT'")


def test_lab_forwarding_not_touching_mgmt_zone_requires_no_approval():
    assert free("firewall.guest_wan=forwarding\nfirewall.guest_wan.src='guest'\nfirewall.guest_wan.dest='wan'",
                "set firewall.guest_wan=forwarding")


def test_lab_unidentified_forwarding_change_requires_approval():
    result = decide("firewall.@forwarding[2].dest='guest'")
    assert result["requires_approval"] is True
    assert any("forwarding" in reason and "management zone" in reason for reason in result["reasons"])


# ---- leash: WAN exposure ----


@pytest.mark.parametrize("diff", [
    "firewall.pf=redirect\nfirewall.pf.src='wan'\nfirewall.pf.dest='lan'\nfirewall.pf.target='DNAT'",
    "firewall.@redirect[0].dest_ip='192.0.2.5'",
    "firewall.allow_web=rule\nfirewall.allow_web.src='wan'\nfirewall.allow_web.target='ACCEPT'",
    "firewall.allow_web=rule\nfirewall.allow_web.src='wan'",
    "firewall.@rule[2].dest_port='22'",
    "firewall.@zone[1].input='ACCEPT'",
    "firewall.@zone[1].forward='ACCEPT'",
    "firewall.wan2=zone\nfirewall.wan2.name='wan'\nfirewall.wan2.input='ACCEPT'",
])
def test_lab_wan_exposure_requires_approval_and_reason_names_it(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("WAN exposure" in reason for reason in result["reasons"])


def test_lab_redirect_from_lan_requires_no_approval():
    assert free("firewall.lanfwd=redirect\nfirewall.lanfwd.src='lan'\nfirewall.lanfwd.dest='lan'",
                "set firewall.lanfwd=redirect")


def test_lab_wan_rule_with_reject_target_requires_no_approval():
    diff = "firewall.block=rule\nfirewall.block.src='wan'\nfirewall.block.target='REJECT'"
    assert free(diff, "set firewall.block=rule")


@pytest.mark.parametrize("diff", [
    "firewall.pf=redirect\nfirewall.pf.src='*'\nfirewall.pf.dest='lan'\nfirewall.pf.target='DNAT'",
    "firewall.pf=redirect\nfirewall.pf.src='*'",
])
def test_lab_wildcard_src_redirect_requires_approval_as_wan_exposure(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("WAN exposure" in reason for reason in result["reasons"])


@pytest.mark.parametrize("diff", [
    "firewall.allow_web=rule\nfirewall.allow_web.src='*'\nfirewall.allow_web.target='ACCEPT'",
    "firewall.allow_web=rule\nfirewall.allow_web.src='*'",
])
def test_lab_wildcard_src_rule_requires_approval_as_wan_exposure(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("WAN exposure" in reason for reason in result["reasons"])


def test_lab_redirect_and_rule_from_lan_stay_free():
    assert free("firewall.lanfwd=redirect\nfirewall.lanfwd.src='lan'\nfirewall.lanfwd.dest='lan'",
                "set firewall.lanfwd=redirect")
    assert free("firewall.lanrule=rule\nfirewall.lanrule.src='lan'\nfirewall.lanrule.target='ACCEPT'",
                "set firewall.lanrule=rule")


@pytest.mark.parametrize("diff", [
    "firewall.allow_web=rule\nfirewall.allow_web.src='wan'\nfirewall.allow_web.target='accept'",
    "firewall.wan2=zone\nfirewall.wan2.name='wan'\nfirewall.wan2.input='accept'",
    "firewall.wan2=zone\nfirewall.wan2.name='wan'\nfirewall.wan2.forward='accept'",
])
def test_lab_lower_case_accept_still_counts_as_wan_exposure(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("WAN exposure" in reason for reason in result["reasons"])


def test_lab_wan_zone_hardened_input_drop_still_requires_approval_as_unidentified():
    """ow-fw-01 shape: the wan zone is found at run time; the diff cannot show which zone it is."""
    result = decide("firewall.@zone[1].input='DROP'")
    assert result["requires_approval"] is True
    assert any("unidentified zone" in reason and "management zone" in reason for reason in result["reasons"])


def test_lab_new_rule_without_src_is_an_output_rule_not_wan_exposure():
    assert free("firewall.rule1='rule'", "set firewall.rule1=rule")


# ---- fail-safe: sections the diff cannot identify ----


@pytest.mark.parametrize("diff", [
    "firewall.cfg0592bd.target='ACCEPT'",
    "-firewall.cfg0592bd",
    "@firewall.cfg0592bd=eviltwin",
    "^firewall.cfg0592bd=0",
    "firewall.my_zone.input='ACCEPT'",
    "firewall.lan_f.network='br-lan'",
])
def test_lab_untyped_firewall_section_change_requires_approval(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("does not show what the section is" in reason for reason in result["reasons"])


def test_lab_unparsed_diff_line_requires_approval():
    result = decide("dhcp.lan.start='50'\ngarbage line without a config dot")
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("unparsed staged change requires approval" in reason for reason in result["reasons"])


@pytest.mark.parametrize("value", ["ACCEPT", "'ACCEPT'"])
def test_quoted_and_unquoted_values_are_both_recognized(value):
    diff = f"firewall.wan2=zone\nfirewall.wan2.name='wan'\nfirewall.wan2.input={value}"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any("WAN exposure" in reason for reason in result["reasons"])


# ---- moved from test_server.py: round-1 approval guarantees ----


@pytest.mark.parametrize("verb_line", [
    "commit system",
    "import /tmp/evil",
    "revert dhcp",
    "export firewall",
    "show dhcp",
    "batch",
])
def test_non_staging_verbs_are_refused(verb_line):
    with pytest.raises(ValueError, match="only set/add/add_list/del_list/delete/rename/reorder are allowed"):
        decide("", f"{verb_line}\nset dhcp.lan.start='50'")


@pytest.mark.parametrize(("batch", "diff"), [
    ("rename dhcp.lan=host", "@dhcp.lan=host"),                      # renders like a new host section in `uci changes`
    ("reorder dhcp.lan=0", "^dhcp.lan=0"),
    ("delete firewall.cfg0592bd", "-firewall.cfg0592bd"),
    ("delete dhcp.lan.leasetime", "-dhcp.lan.leasetime"),
    ("set dhcp.lan.start=50", "dhcp.lan.start='50'"),
    ("add_list dhcp.lan.dhcp_option=6,1.1.1.1", "dhcp.lan.dhcp_option+='6,1.1.1.1'"),
    ("set network.lan.ipaddr=10.9.9.1", "network.lan.ipaddr='10.9.9.1'"),
    ("set uhttpd.main.listen_http=0.0.0.0:80", "uhttpd.main.listen_http='0.0.0.0:80'"),
    ("set dhcp.x=host\nset dhcp.x.interface=wan", "dhcp.x='host'\ndhcp.x.interface='wan'"),
    ("set system.@system[0].log_ip=1.2.3.4", "system.@system[0].log_ip='1.2.3.4'"),
])
def test_batch_outside_approval_free_set_requires_approval_on_prod(batch, diff):
    """Every round-1 'outside the approval-free set' batch still requires approval on prod."""
    result = decide(diff, batch, device=dev(profile="prod"))
    assert result["requires_approval"] is True
    assert result["reasons"][-1] == "profile 'prod': every write requires approval"


@pytest.mark.parametrize(("batch", "diff"), [
    ("set dhcp.nas=host\nset dhcp.nas.name='nas'\nset dhcp.nas.mac='aa:bb:cc:dd:ee:ff'\nset dhcp.nas.ip='192.0.2.20'",
     "dhcp.nas='host'\ndhcp.nas.name='nas'\ndhcp.nas.mac='aa:bb:cc:dd:ee:ff'\ndhcp.nas.ip='192.0.2.20'"),
    ("set system.@system[0].description='lab router'", "system.@system[0].description='lab router'"),
])
def test_approval_free_batches_stay_free_on_lab(batch, diff):
    assert free(diff, batch)


@pytest.mark.parametrize("diff", [
    "-firewall.cfg0592bd",
    "-dhcp.lan.leasetime",
    "dhcp.fmt.dns+='1.1.1.1'",
    "wireless.radio0.channel='6'",
    "@dhcp.fmt=fmt2",
])
def test_diff_gate_deletes_lists_and_other_configs_require_approval_on_prod(diff):
    assert decide(diff, device=dev(profile="prod"))["requires_approval"] is True


def test_diff_gate_deleting_an_unidentified_firewall_section_requires_approval_on_lab():
    assert decide("-firewall.cfg0592bd")["requires_approval"] is True


def test_plan_output_fixture_is_approval_free_on_lab_and_gated_on_prod():
    text = (Path(__file__).parent / "fixtures" / "plan_output.txt").read_text()
    diff = parse_plan(text)["diff"]
    batch = "set dhcp.skilltest=host\nset dhcp.skilltest.name='skilltest'\nset dhcp.skilltest.mac='02:00:00:00:00:99'\nset dhcp.skilltest.ip='192.0.2.99'"
    assert free(diff, batch)
    result = decide(diff, batch, device=dev(profile="prod"))
    assert result["requires_approval"] is True
    assert result["reasons"] == ["profile 'prod': every write requires approval"]


def test_firewall_rule_creation_requires_approval_on_prod():
    result = decide("firewall.rule1='rule'", "set firewall.rule1=rule", device=dev(profile="prod"))
    assert result["requires_approval"] is True
