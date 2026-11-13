"""Hardening tests for the policy review findings
plus the tests of the design 5.2 leash codes.

F2: zone membership by device/subnet and zones that capture the mgmt or wan
network.
F3: firewall ``defaults`` input/forward ACCEPT and ``include`` sections.
F6: network ``device`` / ``bridge-vlan`` sections (bridge/VLAN membership).

The F1 ``check`` allowlist is gone: design 7.2 removed ``check`` and
``check_is_trivial`` from the policy (probes are fixed code validated by
``newton_mcp.probes``); the tests here pin that removal.

The helper shapes mirror mcp/tests/test_policy.py (dev/decide/free).
"""

import inspect

import pytest

from newton_mcp import policy
from newton_mcp.policy import classify
from newton_mcp.server import Device


def dev(profile="lab", mgmt_interface="lan", mgmt_zone="lan", wan_zones=("wan",)):
    return Device("quasar", "openwrt", "192.0.2.1", "root",
                  profile=profile, mgmt_interface=mgmt_interface, mgmt_zone=mgmt_zone,
                  wan_zones=wan_zones)


def decide(diff, batch="", device=None, section_facts=None):
    return classify(device if device is not None else dev(), batch, diff,
                    section_facts=section_facts)


def free(diff, batch="", device=None, section_facts=None):
    return decide(diff, batch, device, section_facts) == {"requires_approval": False, "risk": "low", "reasons": []}


def fires(diff, code, device=None, section_facts=None):
    result = decide(diff, device=device, section_facts=section_facts)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any(reason.startswith(code + ":") for reason in result["reasons"]), result["reasons"]
    return result


# ---- the check parameter and check_is_trivial are gone (design 7.2) ----


def test_check_is_gone_from_classify():
    assert "check" not in inspect.signature(classify).parameters
    assert "section_facts" in inspect.signature(classify).parameters


def test_check_is_trivial_no_longer_exists():
    assert not hasattr(policy, "check_is_trivial")
    assert not hasattr(policy, "_check_segment_is_trivial")


def test_wan_zone_constant_is_gone_the_default_lives_on_the_device():
    assert not hasattr(policy, "WAN_ZONE")
    assert policy.DEFAULT_WAN_ZONES == ("wan",)


# ---- zone membership by device/subnet and mgmt/wan capture ----


@pytest.mark.parametrize("diff", [
    "firewall.@zone[0].device+='eth1'",
    "firewall.@zone[0].subnet+='0.0.0.0/0'",
    "firewall.@zone[0].extra='masq: 1'",
    "firewall.@zone[0].masq_src+='10.0.0.0/8'",
    "firewall.@zone[0].extra_dest='masq: 1'",
    "firewall.@zone[0].masq_dest-='10.0.0.0/8'",
    "-firewall.@zone[0].device",
])
def test_f2_membership_options_on_an_unidentified_zone_require_approval(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("unidentified zone" in reason for reason in result["reasons"])


def test_f2_membership_option_on_the_identified_mgmt_zone_requires_approval():
    diff = "firewall.lanz=zone\nfirewall.lanz.name='lan'\nfirewall.lanz.device+='eth1'"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any("management zone 'lan'" in reason for reason in result["reasons"])


def test_f2_new_zone_lan2_with_lan_network_input_accept_and_forwarding_to_wan():
    diff = (
        "firewall.lan2=zone\nfirewall.lan2.name='lan2'\nfirewall.lan2.network='lan'\n"
        "firewall.lan2.input='ACCEPT'\n"
        "firewall.lan2_wan=forwarding\nfirewall.lan2_wan.src='lan2'\nfirewall.lan2_wan.dest='wan'"
    )
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("new zone 'lan2'" in reason for reason in result["reasons"])


@pytest.mark.parametrize("input_value", ["ACCEPT", "REJECT"])
def test_f2_new_zone_with_wan_network_requires_approval_whatever_the_input(input_value):
    diff = f"firewall.x=zone\nfirewall.x.name='x'\nfirewall.x.network='wan'\nfirewall.x.input='{input_value}'"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any(
        "new zone 'x' lists the 'wan' network" in reason or "new zone 'x' sets input='ACCEPT'" in reason
        for reason in result["reasons"]
    )


def test_f2_new_zone_with_two_network_lines_guest_then_lan_requires_approval():
    diff = (
        "firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.network='guest'\n"
        "firewall.z.network+='lan'\nfirewall.z.input='REJECT'"
    )
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any(
        "lists the management interface 'lan' in its network" in reason
        for reason in result["reasons"]
    )


def test_f2_new_zone_with_lan_and_wan6_in_one_value_requires_approval():
    diff = "firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.network='lan wan6'\nfirewall.z.input='REJECT'"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any(
        "lists the management interface 'lan' in its network" in reason
        for reason in result["reasons"]
    )


def test_f2_new_zone_with_wan6_only_requires_approval():
    diff = "firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.network='wan6'\nfirewall.z.input='REJECT'"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any("lists the 'wan6' network" in reason for reason in result["reasons"])


def test_f2_new_zone_with_input_accept_and_guest_network_requires_approval():
    diff = "firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.network='guest'\nfirewall.z.input='ACCEPT'"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any("new zone 'z' sets input='ACCEPT'" in reason for reason in result["reasons"])


def test_f2_new_zone_with_forward_accept_requires_approval():
    diff = "firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.network='guest'\nfirewall.z.forward='accept'"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any("new zone 'z' sets forward='accept'" in reason for reason in result["reasons"])


def test_f2_new_zone_setting_a_device_requires_approval():
    diff = "firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.device='eth9'\nfirewall.z.input='REJECT'"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any("new zone 'z' sets 'device'" in reason for reason in result["reasons"])


@pytest.mark.parametrize("option", ["subnet", "extra", "extra_src", "extra_dest"])
def test_f2_new_zone_setting_other_capture_options_requires_approval(option):
    diff = f"firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.{option}='0.0.0.0/0'\nfirewall.z.input='REJECT'"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any(f"new zone 'z' sets '{option}'" in reason for reason in result["reasons"])


def test_f2_new_guest_zone_with_guest_network_and_reject_stays_free():
    diff = "firewall.guest=zone\nfirewall.guest.name='guest'\nfirewall.guest.network='guest'\nfirewall.guest.input='REJECT'\nfirewall.guest.forward='REJECT'"
    assert free(diff)


def test_f2_custom_mgmt_interface_new_zone_network_capture():
    device = dev(mgmt_interface="mgmt0")
    captured = "firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.network='mgmt0'\nfirewall.z.input='REJECT'"
    result = decide(captured, device=device)
    assert result["requires_approval"] is True
    assert any(
        "lists the management interface 'mgmt0' in its network" in reason
        for reason in result["reasons"]
    )
    other = "firewall.z2=zone\nfirewall.z2.name='z2'\nfirewall.z2.network='lan'\nfirewall.z2.input='REJECT'\nfirewall.z2.forward='REJECT'"
    assert free(other, device=device)


# ---- firewall defaults ACCEPT and include sections ----


@pytest.mark.parametrize("diff", [
    "firewall.@defaults[0].input='ACCEPT'",
    "firewall.@defaults[0].forward='accept'",
    "firewall.@defaults[0].input=ACCEPT",
    "firewall.dnew=defaults\nfirewall.dnew.input='ACCEPT'",
])
def test_f3_defaults_input_or_forward_accept_requires_approval(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("firewall defaults" in reason and "ACCEPT" in reason for reason in result["reasons"])


@pytest.mark.parametrize("diff", [
    "firewall.i=include\nfirewall.i.path='/etc/x.sh'",
    "firewall.@include[0].path='/etc/y.sh'",
    "firewall.i2=include",
    "-firewall.@include[0]",
])
def test_f3_any_include_change_requires_approval(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("include" in reason for reason in result["reasons"])


@pytest.mark.parametrize("diff", [
    "firewall.@defaults[0].input='REJECT'",
    "firewall.@defaults[0].synflood_protect='1'",
])
def test_f3_other_defaults_changes_stay_free(diff):
    assert free(diff)


def test_f3_deleted_option_fails_safe_now_that_the_committed_value_is_invisible():
    # design 7.2 / round p: the router reads the committed value of a deleted
    # option; the host cannot, so path-option fires fail safe (this line was
    # free when the policy pretended to know the value was gone)
    fires("-firewall.@defaults[0].input", "path-option")


# ---- bridge and VLAN membership ----


@pytest.mark.parametrize("diff", [
    "network.@device[0].ports+='lan4'",
    "network.@device[0].ports-='lan1'",
    "network.@bridge-vlan[0].ports='lan1:t'",
    "network.br2=device\nnetwork.br2.name='br-x'",
    "network.vlan10=bridge-vlan\nnetwork.vlan10.ports='lan1:t'",
])
def test_f6_bridge_and_vlan_membership_changes_require_approval(diff):
    result = decide(diff)
    assert result["requires_approval"] is True
    assert result["risk"] == "critical"
    assert any("bridge/VLAN membership" in reason for reason in result["reasons"])


def test_f6_named_non_mgmt_interface_without_a_shown_type_stays_free():
    assert free("network.guest.ipaddr='10.9.0.1'", "set network.guest.ipaddr='10.9.0.1'")


def test_f2_extra_src_on_an_unidentified_zone_requires_approval():
    result = decide("firewall.@zone[0].extra_src='x'")
    assert result["requires_approval"] is True
    assert any("unidentified zone" in reason for reason in result["reasons"])


@pytest.mark.parametrize("network", ["guest lan", "guest wan6", "guest wan", "x lan y"])
def test_f2_every_name_in_a_network_value_counts_not_only_the_first(network):
    diff = f"firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.network='{network}'\nfirewall.z.input='REJECT'\nfirewall.z.forward='REJECT'"
    result = decide(diff)
    assert result["requires_approval"] is True
    assert any(reason.startswith(("mgmt-zone: ", "zone-exposure: ")) and "lists the " in reason
               for reason in result["reasons"])


@pytest.mark.parametrize("network", ["lan2", "lan2 guest", "wanx", "mywan", "guest lan_b"])
def test_f2_network_names_compare_exactly(network):
    diff = f"firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.network='{network}'\nfirewall.z.input='REJECT'\nfirewall.z.forward='REJECT'"
    assert free(diff)


# ---- round p: every 5.2 code fires, and its benign neighbour does not ----

ZONE_WAN_FACT = {("firewall", "@zone[1]"): ("zone", "wan")}
ZONE_GUEST_FACT = {("firewall", "@zone[2]"): ("zone", "guest")}
FORWARDING_FACT = {("firewall", "@forwarding[0]"): ("forwarding", None)}
RULE_FACT = {("firewall", "@rule[0]"): ("rule", "Allow-DHCP-Renew")}
DEFAULTS_FACT = {("firewall", "@defaults[0]"): ("defaults", None)}


def test_code_mgmt_config_fires_and_system_does_not():
    fires("dropbear.@dropbear[0].Port='2222'", "mgmt-config")
    assert free("system.@system[0].hostname='r2'")


def test_code_mgmt_interface_fires_and_guest_does_not():
    fires("network.lan.ipaddr='10.9.9.1'", "mgmt-interface")
    assert free("network.guest.ipaddr='10.9.0.1'")


def test_code_bridge_member_fires_and_interface_does_not():
    fires("network.@device[0].name='br-x'", "bridge-member",
          section_facts={("network", "@device[0]"): ("device", None)})
    assert free("network.@interface[2].mtu='1400'",
                section_facts={("network", "@interface[2]"): ("interface", None)})


def test_code_mgmt_zone_widened_fires_on_any_option_and_guest_masq_does_not():
    fires("firewall.@zone[0].masq='1'", "mgmt-zone",
          section_facts={("firewall", "@zone[0]"): ("zone", "lan")})
    fires("^firewall.@zone[0]=3", "mgmt-zone",
          section_facts={("firewall", "@zone[0]"): ("zone", "lan")})
    assert free("firewall.@zone[2].masq='1'", section_facts=ZONE_GUEST_FACT)


def test_code_mgmt_zone_identity_by_network_holding_the_mgmt_interface():
    # a zone whose staged network (in the diff) holds the mgmt interface
    fires("firewall.@zone[4].network='lan'\nfirewall.@zone[4].input='ACCEPT'", "mgmt-zone",
          section_facts={("firewall", "@zone[4]"): ("zone", "mgmt2")})


def test_code_wan_zone_fires_on_any_non_exempt_change_and_exempts_tightenings():
    fires("firewall.@zone[1].family='ipv4'", "wan-zone", section_facts=ZONE_WAN_FACT)
    fires("firewall.@zone[1].device='eth9'", "wan-zone", section_facts=ZONE_WAN_FACT)
    fires("-firewall.@zone[1].input", "wan-zone", section_facts=ZONE_WAN_FACT)
    fires("^firewall.@zone[1]=0", "wan-zone", section_facts=ZONE_WAN_FACT)
    assert free("firewall.@zone[1].input='REJECT'", section_facts=ZONE_WAN_FACT)
    assert free("firewall.@zone[1].input='drop'", section_facts=ZONE_WAN_FACT)
    assert free("firewall.@zone[1].log='1'", section_facts=ZONE_WAN_FACT)
    assert free("firewall.@zone[1].masq='0'", section_facts=ZONE_WAN_FACT)


def test_code_zone_exposure_fires_for_existing_and_new_zones_and_stays_quiet_on_tightening():
    fires("firewall.@zone[2].input='ACCEPT'", "zone-exposure", section_facts=ZONE_GUEST_FACT)
    assert free("firewall.@zone[2].input='DROP'", section_facts=ZONE_GUEST_FACT)
    fires("firewall.@zone[2].family='ipv4'", "zone-exposure", section_facts=ZONE_GUEST_FACT)
    fires("firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.input='REJECT'", "zone-exposure")  # no forward
    fires("firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.forward='REJECT'", "zone-exposure")  # no input
    fires("firewall.@zone[2].network+='wan'", "zone-exposure", section_facts=ZONE_GUEST_FACT)
    assert free("firewall.@zone[2].network+='iot'", section_facts=ZONE_GUEST_FACT)


def test_code_forwarding_mgmt_fires_and_guest_to_wan_does_not():
    fires("firewall.f=forwarding\nfirewall.f.src='lan'\nfirewall.f.dest='guest'", "forwarding-mgmt")
    assert free("firewall.f=forwarding\nfirewall.f.src='guest'\nfirewall.f.dest='wan'")


def test_code_wan_forwarding_fires_and_lan_side_does_not():
    fires("firewall.f=forwarding\nfirewall.f.src='wan'\nfirewall.f.dest='guest'", "wan-forwarding")
    fires("firewall.f=forwarding\nfirewall.f.src='*'\nfirewall.f.dest='guest'", "wan-forwarding")


def test_code_wan_redirect_fires_and_lan_redirect_does_not():
    fires("firewall.r=redirect\nfirewall.r.src='wan'\nfirewall.r.dest='lan'", "wan-redirect")
    assert free("firewall.r=redirect\nfirewall.r.src='lan'\nfirewall.r.dest='guest'")


def test_code_wan_rule_fires_incl_delete_reorder_disable_and_reject_target_does_not():
    fires("firewall.r=rule\nfirewall.r.src='wan'\nfirewall.r.target='ACCEPT'", "wan-rule")
    fires("firewall.r=rule\nfirewall.r.src='wan'", "wan-rule")  # no target
    fires("firewall.r=rule\nfirewall.r.src='wan'\nfirewall.r.target='accept'", "wan-rule")
    fires("-firewall.@rule[0]", "wan-rule", section_facts=RULE_FACT)
    fires("^firewall.@rule[0]=0", "wan-rule", section_facts=RULE_FACT)
    fires("firewall.@rule[0].enabled='0'", "wan-rule", section_facts=RULE_FACT)
    fires("firewall.@rule[0].dest_port='69'", "wan-rule", section_facts=RULE_FACT)  # target not in the diff: fail safe
    assert free("firewall.r=rule\nfirewall.r.src='wan'\nfirewall.r.target='REJECT'")
    assert free("firewall.r=rule\nfirewall.r.proto='tcp'")  # no src: an output rule


def test_code_defaults_accept_fires_and_reject_does_not():
    fires("firewall.@defaults[0].input='ACCEPT'", "defaults-accept", section_facts=DEFAULTS_FACT)
    assert free("firewall.@defaults[0].input='DROP'", section_facts=DEFAULTS_FACT)
    assert free("firewall.@defaults[0].synflood_protect='0'", section_facts=DEFAULTS_FACT)


def test_code_exec_include_fires_and_defaults_change_does_not():
    fires("firewall.@include[0].enabled='0'", "exec-include",
          section_facts={("firewall", "@include[0]"): ("include", None)})


def test_code_firewall_type_fires_and_known_types_do_not():
    fires("firewall.n=nat\nfirewall.n.src='wan'", "firewall-type")
    fires("firewall.i=ipset", "firewall-type")
    assert free("firewall.z=zone\nfirewall.z.name='z'\nfirewall.z.input='REJECT'\nfirewall.z.forward='REJECT'")


def test_code_section_unidentified_without_type_or_facts():
    fires("firewall.mysec.input='ACCEPT'", "section-unidentified")
    fires("firewall.cfg0592bd.target='ACCEPT'", "section-unidentified")


def test_code_unparsed_change_fires_and_parsed_lines_do_not():
    fires("garbage line", "unparsed-change")
    assert free("system.@system[0].hostname='r2'")


def test_code_profile_prod_fires_and_lab_does_not():
    result = decide("system.@system[0].hostname='r2'", device=dev(profile="prod"))
    assert result["requires_approval"] is True
    assert result["reasons"] == ["profile 'prod': every write requires approval"]
    assert free("system.@system[0].hostname='r2'")


def test_code_exec_option_fires_per_config_and_neighbour_options_do_not():
    fires("dhcp.@dnsmasq[0].dhcpscript='/bin/true'", "exec-option")
    fires("dhcp.@dnsmasq[0].leasetrigger='/bin/true'", "exec-option")
    fires("system.@system[0].log_file='/tmp/x.log'", "exec-option")
    fires("network.wan.pppd_options='debug'", "exec-option")
    assert free("dhcp.@dnsmasq[0].cachesize='1000'")
    assert free("system.@system[0].log_ip='10.0.0.1'")


def test_code_path_option_fires_and_the_three_exemptions_do_not():
    fires("system.@system[0].timezone='Europe/London'", "path-option")
    fires("dhcp.@dnsmasq[0].address+='/x.lan/1.2.3.4'", "path-option")
    fires("wireless.@wifi-iface[0].ssid='a/b'", "path-option")
    fires("dhcp.@dnsmasq[0].foo='file:///etc/x'", "path-option")
    assert free("dhcp.@dnsmasq[0].foo='10.0.0.0/8'")
    assert free("dhcp.@dnsmasq[0].foo='fd00::/48'")
    assert free("dhcp.@dnsmasq[0].foo='https://dns.example/q'")
    assert free("dhcp.@dnsmasq[0].foo='25/second'")


def test_code_exec_config_and_unknown_package_fire_and_known_ones_do_not():
    fires("ucitrack.@network[0].init='x'", "exec-config")
    fires("foo.thing='whatever'", "unknown-package")
    assert free("luci.main.lang='en'")


def test_code_upnp_on_fires_and_off_does_not():
    fires("upnpd.config.enabled='1'", "upnp-on")
    fires("upnpd.config.enable_natpmp='1'", "upnp-on")
    fires("upnpd.config.enable_upnp='1'", "upnp-on")
    assert free("upnpd.config.enabled='0'")


def test_code_ntp_server_open_fires_and_bound_or_disabled_do_not():
    facts = {("system", "ntp"): ("timeserver", None)}
    fires("system.ntp.enable_server='1'", "ntp-server-open", section_facts=facts)
    assert free("system.ntp.enable_server='0'", section_facts=facts)
    assert free("system.ntp.enable_server='1'\nsystem.ntp.interface='lan'", section_facts=facts)


def test_code_mgmt_route_fires_for_mgmt_interface_and_wan_route_does_not():
    fires("network.rt=route\nnetwork.rt.interface='lan'\nnetwork.rt.target='10.1.0.0/16'", "mgmt-route")
    fires("network.rt=route6\nnetwork.rt.interface='lan'", "mgmt-route")
    assert free("network.rt=route\nnetwork.rt.interface='wan'\nnetwork.rt.target='10.1.0.0/16'")


# ---- section facts: identification, rename handling, fail-safes ----


def test_section_facts_identify_an_existing_zone_so_the_fail_safe_stays_quiet():
    # without facts the diff cannot name the zone -> fail safe
    fires("firewall.@zone[1].input='DROP'", "mgmt-zone")
    # with the router's fact the zone is a named wan zone and the DROP is a
    # permitted tightening
    assert free("firewall.@zone[1].input='DROP'", section_facts=ZONE_WAN_FACT)


def test_section_facts_identify_an_unnamed_zone_fail_safe():
    nameless = {("firewall", "@zone[3]"): ("zone", None)}
    fires("firewall.@zone[3].masq='1'", "section-unidentified", section_facts=nameless)
    assert free("firewall.@zone[2].masq='1'", section_facts=ZONE_GUEST_FACT)


def test_section_rename_groups_under_the_old_name_and_reads_the_new_name():
    diff = "@firewall.@zone[2]=guestzone\nfirewall.guestzone.input='ACCEPT'"
    fires(diff, "zone-exposure", section_facts={("firewall", "guestzone"): ("zone", "guest")})
    diff = "@firewall.@zone[0]=lanzone\nfirewall.lanzone.masq='1'"
    fires(diff, "mgmt-zone", section_facts={("firewall", "lanzone"): ("zone", "lan")})


def test_option_rename_counts_as_a_change_to_both_options():
    fires("@dhcp.@dnsmasq[0].foo=dhcpscript", "exec-option",
          section_facts={("dhcp", "@dnsmasq[0]"): ("dnsmasq", None)})


def test_reorder_counts_as_reordering():
    fires("^firewall.@zone[1]=0", "wan-zone", section_facts=ZONE_WAN_FACT)


def test_wan_zones_come_from_the_device_two_zone_list():
    device = dev(wan_zones=("wan", "extern"))
    fires("firewall.f=forwarding\nfirewall.f.src='extern'\nfirewall.f.dest='guest'",
          "wan-forwarding", device=device)
    # with the default list 'extern' is an ordinary zone: guest->extern is free
    assert free("firewall.f=forwarding\nfirewall.f.src='guest'\nfirewall.f.dest='extern'")


def test_wan_zones_come_from_the_device_zone_named_differently_from_wan():
    device = dev(wan_zones=("wan", "extern"))
    facts = {("firewall", "@zone[2]"): ("zone", "extern")}
    fires("firewall.@zone[2].family='ipv4'", "wan-zone", device=device, section_facts=facts)
    fires("^firewall.@zone[2]=0", "wan-zone", device=device, section_facts=facts)
    # without 'extern' in the list the same reorder is an ordinary zone change
    assert free("^firewall.@zone[2]=0", section_facts=facts)


def test_bare_simple_namespace_without_wan_zones_still_works():
    import types
    device = types.SimpleNamespace(profile="lab", mgmt_interface="lan", mgmt_zone="lan")
    result = classify(device, "set a.b.c=1", "firewall.f=forwarding\nfirewall.f.src='wan'\nfirewall.f.dest='guest'")
    assert result["requires_approval"] is True


def test_invalid_wan_zones_is_an_inventory_error():
    import types
    device = types.SimpleNamespace(profile="lab", mgmt_interface="lan", mgmt_zone="lan", wan_zones="wan")
    with pytest.raises(ValueError, match="wan_zones"):
        classify(device, "set a.b.c=1", "")


# ---- newton_wanhealth is a known package, not an unknown one ---------
# The WAN-health package is installed by newton-router-setup and is enabled
# through a normal Newton change. Before the fix the package name was missing
# from KNOWN_PACKAGES, so any change fired the unknown-package leash code
# and the host policy added an "unknown-package: ..." reason. The package is
# now known; an unknown-package reason must not fire for it, but a batch
# that mixes newton_wanhealth with a still-risky package is still gated by
# the risky part (sanity for "no regression on neighbour reasons"). A truly
# unknown package name must still fire unknown-package so the test pin holds.


def test_wanhealth_change_does_not_fire_unknown_package_on_lab():
    diff = (
        "newton_wanhealth.main=settings\n"
        "newton_wanhealth.main.enabled='1'\n"
        "newton_wanhealth.main.interval='3'\n"
        "newton_wanhealth.main.timeout='1'\n"
    )
    result = decide(diff, device=dev(profile="lab"))
    assert result["requires_approval"] is False, result
    assert not any(reason.startswith("unknown-package:") for reason in result["reasons"]), result


def test_wanhealth_change_still_requires_approval_on_prod():
    diff = (
        "newton_wanhealth.main=settings\n"
        "newton_wanhealth.main.enabled='1'\n"
    )
    result = decide(diff, device=dev(profile="prod"))
    assert result["requires_approval"] is True, result
    assert any(
        reason.startswith("profile 'prod': every write requires approval")
        for reason in result["reasons"]
    ), result
    assert not any(reason.startswith("unknown-package:") for reason in result["reasons"]), result


def test_truly_unknown_package_still_fires_unknown_package():
    # A package that is NOT newton_wanhealth (and not in KNOWN_PACKAGES) must
    # still trip the unknown-package code; the reason is the whole point of
    # the unknown-package leash signal.
    result = decide("foo.thing='whatever'", device=dev(profile="lab"))
    assert result["requires_approval"] is True
    assert any(reason.startswith("unknown-package:") for reason in result["reasons"]), result


def test_wanhealth_mixed_with_risky_package_is_still_gated_by_risky_part():
    # The risk of a batch is the max of its parts. A change that adds a
    # newton_wanhealth line and a dropbear line must still require approval
    # because dropbear is a management config; the wanhealth part no longer
    # contributes a reason of its own.
    diff = (
        "newton_wanhealth.main.enabled='1'\n"
        "dropbear.@dropbear[0].Port='2222'\n"
    )
    result = decide(diff, device=dev(profile="lab"))
    assert result["requires_approval"] is True
    assert any(reason.startswith("mgmt-config:") for reason in result["reasons"]), result
    assert not any(reason.startswith("unknown-package:") for reason in result["reasons"]), result
