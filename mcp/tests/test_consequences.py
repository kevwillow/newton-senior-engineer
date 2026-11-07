"""Plain-language descriptions and smaller alternatives for staged UCI changes."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from exhelp import explained

from newton_mcp import consequences, server
from newton_mcp.plan import compute_plan_hash


SID = "0123456789abcdef0123456789abcdef"
BASE_HASH = "b" * 64

FORWARD_LINE = "Opens a port from the internet to a device on your network."
DMZ_LINE = "Sends ALL unsolicited internet traffic to one device on your network."
WAN_ACCEPT_LINE = "Lets the internet connect to the router or to devices on your network."
MGMT_LINE = "Changes who can reach the router's login pages or SSH."
GUEST_LINE = "Gives a new, separate network internet access."
DHCP_HOST_LINE = "Reserves a fixed address for a device."
DNS_LINE = "Changes how names are looked up on your network."
LAN_LINE = "Changes a network address of the router: a mistake can cut you off from it."
WIFI_LINE = "Changes Wi-Fi name, password, security or radio settings."
HOSTNAME_LINE = "Renames the router."
LABEL_LINE = "Changes the router's description or notes text, a label only."
FIREWALL_LINE = "Changes the firewall rules."
UNEXPLAINED_LINE = "Some changes are not described here: read the config lines below."
FALLBACK_LINE = "Newton cannot describe this change in plain words: read the config lines below."

FORWARD_ALT = "Smaller alternative: reach it through a WireGuard/VPN connection instead of opening a public port."
DMZ_ALT = "Smaller alternative: forward only the single port that device needs."
WAN_ACCEPT_ALT = "Smaller alternative: allow it from the VPN only."
MGMT_ALT = "Smaller alternative: keep the admin pages on the LAN and reach them over a VPN."


def test_fw_forward_wan_describes_a_public_port_forward():
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='wan'",
            "set firewall.port.target='DNAT'",
            "set firewall.port.dest_port='443'",
        ]
    )

    assert consequences.describe(batch) == [FORWARD_LINE]
    assert consequences.alternatives(batch) == [FORWARD_ALT]


def test_fw_forward_wan_also_matches_a_wan_redirect_with_another_target():
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='wan'",
            "set firewall.port.target='ACCEPT'",
        ]
    )

    assert FORWARD_LINE in consequences.describe(batch)


def test_fw_dmz_describes_a_whole_host_forward():
    batch = "\n".join(
        [
            "set firewall.dmz=redirect",
            "set firewall.dmz.src='wan'",
            "set firewall.dmz.dest_ip='192.0.2.10'",
        ]
    )

    assert consequences.describe(batch) == [FORWARD_LINE, DMZ_LINE]
    assert consequences.alternatives(batch) == [FORWARD_ALT, DMZ_ALT]


def test_fw_dmz_does_not_match_a_forward_with_a_source_port():
    batch = "\n".join(
        [
            "set firewall.dmz=redirect",
            "set firewall.dmz.src='wan'",
            "set firewall.dmz.dest_ip='192.0.2.10'",
            "set firewall.dmz.src_dport='443'",
        ]
    )

    assert DMZ_LINE not in consequences.describe(batch)
    assert DMZ_ALT not in consequences.alternatives(batch)


def test_fw_wan_accept_describes_internet_access_to_the_router():
    batch = "\n".join(
        [
            "set firewall.open=rule",
            "set firewall.open.src='wan'",
            "set firewall.open.target='ACCEPT'",
        ]
    )

    assert consequences.describe(batch) == [WAN_ACCEPT_LINE]
    assert consequences.alternatives(batch) == [WAN_ACCEPT_ALT]


def test_fw_wan_accept_also_matches_a_rule_with_a_destination():
    batch = "\n".join(
        [
            "set firewall.open=rule",
            "set firewall.open.src='wan'",
            "set firewall.open.target='ACCEPT'",
            "set firewall.open.dest='lan'",
        ]
    )

    assert WAN_ACCEPT_LINE in consequences.describe(batch)


def test_wan_zone_accepting_input_is_described_not_called_a_plain_firewall_change():
    batch = "\n".join(
        [
            "set firewall.wanz=zone",
            "set firewall.wanz.name='wan'",
            "set firewall.wanz.input='ACCEPT'",
        ]
    )

    assert consequences.describe(batch) == [
        "Makes the internet side of the router accept incoming connections."
    ]


def test_a_delete_is_never_invisible():
    batch = "\n".join(
        [
            "set system.@system[0].hostname='synthetic-router-name'",
            "delete firewall.@rule[0]",
        ]
    )

    lines = consequences.describe(batch)
    assert "Removes existing settings from the router." in lines
    assert consequences.describe("delete firewall.@rule[0]") == [
        "Removes existing settings from the router.",
        UNEXPLAINED_LINE,
    ]


def test_a_bare_uhttpd_port_and_gateway_ports_clients_count_as_exposure():
    bare = "\n".join(["set uhttpd.main=uhttpd", "set uhttpd.main.listen_http='80'"])
    clients = "\n".join(["set dropbear.ssh=dropbear", "set dropbear.ssh.GatewayPorts='clients'"])

    assert MGMT_LINE in consequences.describe(bare)
    assert MGMT_LINE in consequences.describe(clients)


def test_mgmt_wan_describes_public_management_access():
    batch = "\n".join(
        [
            "set uhttpd.web=uhttpd",
            "set uhttpd.web.Interface='0.0.0.0'",
        ]
    )

    assert consequences.describe(batch) == [MGMT_LINE]
    assert consequences.alternatives(batch) == [MGMT_ALT]


def test_mgmt_wan_does_not_match_a_lan_only_management_interface():
    batch = "\n".join(
        [
            "set uhttpd.web=uhttpd",
            "set uhttpd.web.Interface='lan'",
        ]
    )

    assert MGMT_LINE not in consequences.describe(batch)
    assert MGMT_ALT not in consequences.alternatives(batch)


def test_mgmt_wan_describes_public_dropbear_ssh():
    batch = "\n".join(
        [
            "set dropbear.ssh=dropbear",
            "set dropbear.ssh.Interface='0.0.0.0'",
        ]
    )

    assert consequences.describe(batch) == [MGMT_LINE]
    assert consequences.alternatives(batch) == [MGMT_ALT]


def test_mgmt_wan_describes_dropbear_gateway_ports_without_an_interface():
    batch = "\n".join(
        [
            "set dropbear.ssh=dropbear",
            "set dropbear.ssh.GatewayPorts='on'",
        ]
    )

    assert consequences.describe(batch) == [MGMT_LINE]
    assert consequences.alternatives(batch) == [MGMT_ALT]


def test_guest_iso_describes_guest_internet_without_lan_access():
    batch = "\n".join(
        [
            "set firewall.guest=zone",
            "set firewall.guest.name='guest'",
            "set firewall.guest.input='REJECT'",
            "set firewall.guest.forward='REJECT'",
            "set firewall.guest_wan=forwarding",
            "set firewall.guest_wan.src='guest'",
            "set firewall.guest_wan.dest='wan'",
        ]
    )

    assert consequences.describe(batch) == [GUEST_LINE]
    assert consequences.alternatives(batch) == []


def test_guest_iso_does_not_match_a_zone_that_can_also_reach_the_lan():
    batch = "\n".join(
        [
            "set firewall.guest=zone",
            "set firewall.guest.name='guest'",
            "set firewall.guest.input='REJECT'",
            "set firewall.guest.forward='ACCEPT'",
            "set firewall.guest_wan=forwarding",
            "set firewall.guest_wan.src='guest'",
            "set firewall.guest_wan.dest='wan'",
            "set firewall.guest_lan=forwarding",
            "set firewall.guest_lan.src='guest'",
            "set firewall.guest_lan.dest='lan'",
        ]
    )

    assert GUEST_LINE not in consequences.describe(batch)


def test_dhcp_host_describes_a_fixed_address_reservation():
    batch = "\n".join(
        [
            "set dhcp.printer=host",
            "set dhcp.printer.name='printer'",
        ]
    )

    assert consequences.describe(batch) == [DHCP_HOST_LINE]
    assert consequences.alternatives(batch) == []


def test_dhcp_host_does_not_match_an_ordinary_dhcp_section():
    batch = "\n".join(
        [
            "set dhcp.pool=dhcp",
            "set dhcp.pool.start='100'",
        ]
    )

    assert DHCP_HOST_LINE not in consequences.describe(batch)


def test_dns_describes_a_dnsmasq_name_server_change():
    batch = "set dhcp.@dnsmasq[0].server='192.0.2.53'"

    assert consequences.describe(batch) == [DNS_LINE]
    assert consequences.alternatives(batch) == []


def test_dns_does_not_match_an_unrelated_dnsmasq_option():
    batch = "set dhcp.@dnsmasq[0].lease_time='12h'"

    assert DNS_LINE not in consequences.describe(batch)


def test_lan_addr_describes_a_network_address_change():
    batch = "\n".join(
        [
            "set network.lan=interface",
            "set network.lan.proto='static'",
        ]
    )

    assert consequences.describe(batch) == [LAN_LINE]
    assert consequences.alternatives(batch) == []


def test_lan_addr_does_not_match_an_unrelated_network_section():
    batch = "\n".join(
        [
            "set network.notes=note",
            "set network.notes.value='synthetic'",
        ]
    )

    assert LAN_LINE not in consequences.describe(batch)


def test_wifi_describes_a_wireless_interface_change():
    batch = "\n".join(
        [
            "set wireless.ap=wifi-iface",
            "set wireless.ap.ssid='synthetic-ssid'",
        ]
    )

    assert consequences.describe(batch) == [WIFI_LINE]
    assert consequences.alternatives(batch) == []


def test_wifi_does_not_match_an_unrelated_wireless_option():
    batch = "\n".join(
        [
            "set wireless.ap=wifi-iface",
            "set wireless.ap.mode='ap'",
        ]
    )

    assert WIFI_LINE not in consequences.describe(batch)


def test_hostname_describes_a_router_rename():
    batch = "set system.@system[0].hostname='synthetic-router-name'"

    assert consequences.describe(batch) == [HOSTNAME_LINE]
    assert consequences.alternatives(batch) == []


def test_hostname_does_not_match_another_system_option():
    batch = "set system.@system[0].description='synthetic-description'"

    assert HOSTNAME_LINE not in consequences.describe(batch)


def test_system_label_describes_a_description_or_notes_change():
    """The owner's dialog test set a description and got the
    cannot-describe fallback for a change that is only a label."""
    for batch in (
        "set system.@system[0].description='synthetic-description'",
        "set system.@system[0].notes='synthetic notes'",
    ):
        assert consequences.describe(batch) == [LABEL_LINE], batch
        assert consequences.alternatives(batch) == []


def test_no_rule_claims_a_batch_with_a_rename_or_reorder_is_fully_described():
    """Rename and reorder carry no facts, so a rule could
    cover every fact while a rename turns a label into a working option
    (description -> log_ip).  The label line is never shown then, and the
    other rules get the not-described line."""
    renamed = "\n".join(
        [
            "set system.@system[0].description='10.0.0.9'",
            "rename system.@system[0].description=log_ip",
        ]
    )
    assert LABEL_LINE not in consequences.describe(renamed)
    assert consequences.describe(renamed) == [FALLBACK_LINE]
    # the router splits a line on any whitespace, so a tab is a rename too
    tabbed = renamed.replace("rename ", "rename\t")
    assert consequences.describe(tabbed) == [FALLBACK_LINE]


def test_a_tab_separated_delete_is_still_a_delete():
    batch = "\n".join(
        [
            "set system.@system[0].hostname='synthetic-router-name'",
            "delete\tsystem.@system[0].log_ip",
        ]
    )
    assert consequences.describe(batch)[0] == consequences.DELETES_LINE

    reordered = "\n".join(
        [
            "set system.@system[0].hostname='synthetic-router-name'",
            "reorder system.@system[0]=1",
        ]
    )
    assert consequences.describe(reordered) == [HOSTNAME_LINE, UNEXPLAINED_LINE]


def test_system_label_does_not_match_a_named_section_of_unknown_type():
    """An existing named section could be an LED or anything else; the
    batch alone does not say it is the system section."""
    for batch in (
        "set system.led_wan.description='synthetic-description'",
        "set system.cfg01e48a.description='synthetic-description'",
    ):
        assert LABEL_LINE not in consequences.describe(batch), batch


def test_system_label_does_not_match_another_section_type():
    batch = "\n".join(
        [
            "set system.led_wan=led",
            "set system.led_wan.description='synthetic-description'",
        ]
    )

    assert LABEL_LINE not in consequences.describe(batch)


def test_system_label_leaves_other_system_options_undescribed():
    batch = "\n".join(
        [
            "set system.@system[0].description='synthetic-description'",
            "set system.@system[0].timezone='UTC'",
        ]
    )

    assert consequences.describe(batch) == [LABEL_LINE, UNEXPLAINED_LINE]


def test_fw_other_describes_an_unclassified_firewall_change():
    batch = "\n".join(
        [
            "set firewall.lan_access=rule",
            "set firewall.lan_access.src='lan'",
            "set firewall.lan_access.target='ACCEPT'",
        ]
    )

    assert consequences.describe(batch) == [FIREWALL_LINE]
    assert consequences.alternatives(batch) == []


def test_fw_other_does_not_match_a_non_firewall_section():
    batch = "set includes.missing=include"

    assert FIREWALL_LINE not in consequences.describe(batch)


def test_an_empty_batch_has_only_the_cannot_describe_fallback():
    assert consequences.describe("") == [FALLBACK_LINE]


def test_an_unknown_change_has_only_the_cannot_describe_fallback():
    assert consequences.describe("set mystery.thing.value='synthetic'") == [FALLBACK_LINE]


def test_a_change_no_rule_explains_adds_the_last_line_notice():
    batch = "\n".join(
        [
            "set system.@system[0].hostname='synthetic-router-name'",
            "set mystery.thing.value='synthetic'",
        ]
    )

    assert consequences.describe(batch) == [HOSTNAME_LINE, UNEXPLAINED_LINE]


def test_descriptions_are_limited_to_three_lines_in_rule_order():
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='wan'",
            "set firewall.port.target='DNAT'",
            "set firewall.open=rule",
            "set firewall.open.src='wan'",
            "set firewall.open.target='ACCEPT'",
            "set dropbear.ssh=dropbear",
            "set dropbear.ssh.GatewayPorts='on'",
            "set system.@system[0].hostname='synthetic-router-name'",
        ]
    )

    assert consequences.describe(batch) == [
        FORWARD_LINE,
        WAN_ACCEPT_LINE,
        MGMT_LINE,
    ]


def test_rule_order_is_stable_across_calls_and_batch_line_order():
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='wan'",
            "set firewall.port.target='DNAT'",
            "set system.@system[0].hostname='synthetic-router-name'",
        ]
    )
    reversed_batch = "\n".join(reversed(batch.splitlines()))

    expected = [FORWARD_LINE, HOSTNAME_LINE]
    assert consequences.describe(batch) == expected
    assert consequences.describe(batch) == expected
    assert consequences.describe(reversed_batch) == expected


def test_a_dmz_is_distinguished_from_a_single_port_forward():
    single_port = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='wan'",
            "set firewall.port.target='DNAT'",
            "set firewall.port.dest_port='443'",
        ]
    )
    dmz = "\n".join(
        [
            "set firewall.dmz=redirect",
            "set firewall.dmz.src='wan'",
            "set firewall.dmz.dest_ip='192.0.2.10'",
        ]
    )

    assert consequences.describe(single_port) == [FORWARD_LINE]
    assert DMZ_LINE not in consequences.describe(single_port)
    assert consequences.describe(dmz) == [FORWARD_LINE, DMZ_LINE]


def test_no_config_value_appears_in_a_description_or_alternative():
    hostname = "synthetic-private-hostname"
    ssid = "synthetic-private-ssid"
    key = "synthetic-private-key"
    batch = "\n".join(
        [
            f"set system.@system[0].hostname='{hostname}'",
            "set wireless.ap=wifi-iface",
            f"set wireless.ap.ssid='{ssid}'",
            f"set wireless.ap.key='{key}'",
        ]
    )

    output = "\n".join(consequences.describe(batch) + consequences.alternatives(batch))
    assert hostname not in output
    assert ssid not in output
    assert key not in output


def test_a_placeholder_value_does_not_match_a_rule_that_needs_its_value():
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='{source}'",
        ]
    )

    assert FORWARD_LINE not in consequences.describe(batch)
    assert FORWARD_ALT not in consequences.alternatives(batch)


def _plan_output(diff: str) -> str:
    return (
        "BACKUP /tmp/fake.tar (2 config files)\n"
        f"STAGED session={SID}\n"
        f"BASEHASH {BASE_HASH}\n"
        f"PROBES 0 {'a' * 64}\n"
        "PROFILE prod\n"
        "APPROVAL not-required\n"
        f"PLANDIGEST {'d' * 64}\n"
        "----- diff -----\n"
        f"{diff}\n"
        "----------------\n"
    )


def _plan_result(
    monkeypatch,
    batch: str,
    *,
    intent: str | None = None,
) -> dict[str, Any]:
    diff = batch
    monkeypatch.setattr(
        server.NewtonService,
        "run_script",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, _plan_output(diff), ""
        ),
    )
    kwargs = explained(batch)
    if intent is not None:
        kwargs["explanation"]["intent"] = intent
    return server.NewtonService().plan("quasar", batch, **kwargs)


def test_the_plan_result_carries_both_consequence_fields(configured_newton, monkeypatch):
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='wan'",
            "set firewall.port.target='DNAT'",
        ]
    )

    planned = _plan_result(monkeypatch, batch)

    assert planned["what_this_does"] == [FORWARD_LINE]
    assert planned["smaller_alternatives"] == [FORWARD_ALT]


def test_the_consequence_fields_are_not_stored_in_the_plan_record(configured_newton, monkeypatch):
    batch = "set system.@system[0].hostname='synthetic-router-name'"

    _plan_result(monkeypatch, batch)

    record = json.loads(
        (Path(configured_newton) / "state" / "plans" / f"{SID}.json").read_text()
    )
    assert "what_this_does" not in record
    assert "smaller_alternatives" not in record
    assert record["plan_hash"] == compute_plan_hash(record)


def test_the_plan_result_never_uses_the_agent_explanation(configured_newton, monkeypatch):
    batch = "set system.@system[0].hostname='synthetic-router-name'"

    planned = _plan_result(
        monkeypatch,
        batch,
        intent="guests are isolated from the other devices",
    )

    assert planned["what_this_does"] == [HOSTNAME_LINE]
    assert GUEST_LINE not in planned["what_this_does"]
