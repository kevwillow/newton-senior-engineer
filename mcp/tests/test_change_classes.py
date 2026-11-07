"""Classification of a staged change into grantable classes.

The classifier reads the staged config lines and nothing else: no device
is contacted and no agent prose is trusted.  Every line in this file is
synthetic.
"""

from __future__ import annotations

import pytest

from newton_mcp import change_classes


DHCP_HOST = "\n".join(
    [
        "set dhcp.host1=host",
        "set dhcp.host1.mac='aa:bb:cc:dd:ee:01'",
        "set dhcp.host1.ip='192.0.2.20'",
        "set dhcp.host1.name='printer'",
    ]
)

DNS_UPSTREAM = "\n".join(
    [
        "set dhcp.@dnsmasq[0].server='1.1.1.1'",
        "set dhcp.@dnsmasq[0].domain='home'",
    ]
)

DNS_RECORD = "\n".join(
    [
        "set dhcp.@domain[0].name='nas'",
        "set dhcp.@domain[0].ip='192.0.2.5'",
    ]
)

HOSTNAME = "set system.main.hostname='router'"

WIFI = "\n".join(
    [
        "set wireless.@wifi-iface[0].ssid='newton-test-2g'",
        "set wireless.@wifi-iface[0].key='synthetic-password'",
    ]
)


def _classes(batch: str) -> frozenset[str]:
    return change_classes.classify(batch).classes


def _grantable(batch: str) -> bool:
    return change_classes.classify(batch).grantable


def _reasons(batch: str) -> tuple[str, ...]:
    return change_classes.classify(batch).high_reasons


# --- the classes -------------------------------------------------------------


def test_a_dhcp_host_is_the_dhcp_reservations_class():
    result = change_classes.classify(DHCP_HOST)

    assert result.classes == frozenset({"dhcp-reservations"})
    assert result.grantable is True
    assert result.high is False
    assert result.high_reasons == ()


def test_a_dhcp_host_option_off_the_list_is_not_grantable():
    batch = "\n".join(
        [
            "set dhcp.host1=host",
            "set dhcp.host1.mac='aa:bb:cc:dd:ee:01'",
            "set dhcp.host1.uid='1000'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.classes == frozenset({"dhcp-reservations"})
    assert result.grantable is False


def test_a_batch_cannot_re_type_a_section_the_router_holds():
    """The router's type wins: a batch cannot turn a pool into a host.

    A batch that says `set dhcp.lan=host` for a section the router
    holds as a `dhcp` pool would change what the section is, and the
    allowlist would then see a host.  The change is not grantable.
    """
    classification = change_classes.classify(
        "set dhcp.lan=host\nset dhcp.lan.leasetime='1m'",
        {("dhcp", "lan"): "dhcp"},
    )
    assert classification.grantable is False, classification
    assert "dhcp-reservations" not in classification.classes, classification


def test_a_dhcp_section_type_off_the_list_is_not_grantable():
    batch = "\n".join(
        [
            "set dhcp.thing=pool",
            "set dhcp.thing.start='100'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.classes == frozenset()
    assert result.grantable is False


def test_dns_upstreams_are_the_dns_class():
    result = change_classes.classify(DNS_UPSTREAM)

    assert result.classes == frozenset({"dns"})
    assert result.grantable is True


def test_a_local_dns_record_is_the_dns_class():
    result = change_classes.classify(DNS_RECORD)

    assert result.classes == frozenset({"dns"})
    assert result.grantable is True


def test_a_dns_option_off_the_list_is_not_grantable():
    batch = "\n".join(
        [
            "set dhcp.@dnsmasq[0].server='1.1.1.1'",
            "set dhcp.@dnsmasq[0].bogus='x'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.grantable is False


def test_a_dns_record_option_off_the_list_is_not_grantable():
    batch = "\n".join(
        [
            "set dhcp.@domain[0].name='nas'",
            "set dhcp.@domain[0].mac='aa:bb:cc:dd:ee:02'",
        ]
    )

    assert change_classes.classify(batch).grantable is False


def test_the_router_name_is_the_hostname_class():
    result = change_classes.classify(HOSTNAME)

    assert result.classes == frozenset({"hostname"})
    assert result.grantable is True


def test_the_router_name_class_does_not_constrain_the_section_type():
    # The option alone is enough; a section-level line beside it would
    # create or retype a section, which the wildcard never covers (see test_the_hostname_wildcard_does_not_cover_...).
    for batch in (
        "set system.main.hostname='router'",
        "set system.@system[0].hostname='router'",
    ):
        result = change_classes.classify(batch)

        assert result.classes == frozenset({"hostname"})
        assert result.grantable is True


def test_another_system_option_is_not_grantable():
    batch = "\n".join(
        [
            "set system.main=system",
            "set system.main.description='lab'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.grantable is False


def test_wifi_name_and_key_are_the_wifi_class():
    result = change_classes.classify(WIFI)

    assert result.classes == frozenset({"wifi-name-key"})
    assert result.grantable is True


def test_wifi_encryption_is_not_grantable():
    batch = "\n".join(
        [
            "set wireless.@wifi-iface[0].ssid='newton-test-2g'",
            "set wireless.@wifi-iface[0].encryption='psk2'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.classes == frozenset({"wifi-name-key"})
    assert result.grantable is False


def test_a_wifi_radio_option_is_not_grantable():
    batch = "set wireless.@wifi-device[0].channel='6'"

    result = change_classes.classify(batch)

    assert result.classes == frozenset()
    assert result.grantable is False


def test_a_mixed_batch_of_a_granted_and_an_unlisted_line_is_not_grantable():
    batch = "\n".join(
        [
            "set dhcp.host1=host",
            "set dhcp.host1.mac='aa:bb:cc:dd:ee:01'",
            "set network.lan.ipaddr='192.0.2.1'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.classes == frozenset({"dhcp-reservations"})
    assert result.grantable is False


def test_a_delete_is_never_grantable():
    batch = "\n".join(
        [
            "set dhcp.host1=host",
            "set dhcp.host1.mac='aa:bb:cc:dd:ee:01'",
            "delete dhcp.host1",
        ]
    )

    result = change_classes.classify(batch)

    assert result.grantable is False


def test_a_rename_is_never_grantable():
    batch = "\n".join(
        [
            "set dhcp.host1=host",
            "rename dhcp.host1=host2",
        ]
    )

    assert change_classes.classify(batch).grantable is False


def test_add_dhcp_host_is_grantable():
    result = change_classes.classify("add dhcp host")

    assert result.classes == frozenset({"dhcp-reservations"})
    assert result.grantable is True


def test_add_dhcp_domain_is_grantable():
    result = change_classes.classify("add dhcp domain")

    assert result.classes == frozenset({"dns"})
    assert result.grantable is True


def test_add_firewall_rule_is_not_grantable():
    result = change_classes.classify("add firewall rule")

    assert result.grantable is False


def test_add_of_a_dhcp_section_that_is_not_offered_is_not_grantable():
    result = change_classes.classify("add dhcp dnsmasq")

    assert result.grantable is False


def test_a_placeholder_left_in_the_batch_is_not_grantable():
    batch = "\n".join(
        [
            "set dhcp.host1=host",
            "set dhcp.host1.ip='{ip}'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.classes == frozenset({"dhcp-reservations"})
    assert result.grantable is False


def test_a_placeholder_in_a_dhcp_host_is_not_grantable():
    batch = "\n".join(
        [
            "set dhcp.host1=host",
            "set dhcp.host1.name='printer'",
            "set dhcp.host1.ip='{ip}'",
        ]
    )

    assert change_classes.classify(batch).grantable is False


# --- HIGH --------------------------------------------------------------------


def test_a_firewall_redirect_is_internet_exposure():
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set firewall.port.src='wan'",
            "set firewall.port.dest_port='443'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.high is True
    assert result.high_reasons == ("internet-exposure",)
    assert result.grantable is False


def test_a_wan_accept_rule_is_internet_exposure():
    batch = "\n".join(
        [
            "set firewall.open=rule",
            "set firewall.open.src='wan'",
            "set firewall.open.target='ACCEPT'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.high is True
    assert result.high_reasons == ("internet-exposure",)


def test_a_wan_rule_that_does_not_accept_is_not_internet_exposure():
    batch = "\n".join(
        [
            "set firewall.open=rule",
            "set firewall.open.src='wan'",
            "set firewall.open.target='REJECT'",
        ]
    )

    assert change_classes.classify(batch).high is False


def test_a_wan_zone_that_accepts_is_internet_exposure():
    batch = "\n".join(
        [
            "set firewall.@zone[1].name='wan'",
            "set firewall.@zone[1].input='ACCEPT'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.high is True
    assert result.high_reasons == ("internet-exposure",)


def test_a_wan_zone_that_only_forwards_is_internet_exposure():
    batch = "\n".join(
        [
            "set firewall.@zone[1].name='wan'",
            "set firewall.@zone[1].forward='ACCEPT'",
        ]
    )

    assert change_classes.classify(batch).high_reasons == ("internet-exposure",)


def test_an_upnp_change_is_internet_exposure():
    batch = "\n".join(
        [
            "set upnpd.config=upnpd",
            "set upnpd.config.enabled='1'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.high is True
    assert result.high_reasons == ("internet-exposure",)


def test_a_miniupnp_change_is_internet_exposure():
    batch = "set miniupnpd.config.enabled='1'"

    assert change_classes.classify(batch).high_reasons == ("internet-exposure",)


def test_a_uhttpd_change_is_management_access():
    batch = "\n".join(
        [
            "set uhttpd.main.listen_http='0.0.0.0:8080'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.high is True
    assert result.high_reasons == ("management-access",)


def test_a_dropbear_change_is_management_access():
    batch = "set dropbear.@dropbear[0].GatewayPorts='clients'"

    assert change_classes.classify(batch).high_reasons == ("management-access",)


def test_an_rpcd_change_is_management_access():
    batch = "set rpcd.@type[0].enabled='1'"

    assert change_classes.classify(batch).high_reasons == ("management-access",)


def test_a_delete_of_a_firewall_path_is_management_access():
    batch = "delete firewall.@rule[0]"

    result = change_classes.classify(batch)

    assert result.high is True
    assert result.high_reasons == ("management-access",)
    assert result.grantable is False


def test_a_delete_of_a_uhttpd_path_is_management_access():
    batch = "delete uhttpd.main"

    assert change_classes.classify(batch).high_reasons == ("management-access",)


def test_a_delete_of_a_dropbear_path_is_management_access():
    batch = "delete dropbear.@dropbear[0]"

    assert change_classes.classify(batch).high_reasons == ("management-access",)


def test_an_option_that_runs_commands_is_high():
    batch = "set dhcp.main.dhcp_script='/usr/bin/thing'"

    result = change_classes.classify(batch)

    assert result.high is True
    assert result.high_reasons == ("runs-commands",)
    assert result.grantable is False


@pytest.mark.parametrize(
    "option",
    [
        "dhcp_script",
        "script",
        "init",
        "hotplug",
        "exec",
        "cmd",
        "command",
        "path",
        "include",
        "lease_script",
        "dhcpscript",
        "userscript",
    ],
)
def test_every_option_that_runs_commands_is_high(option):
    batch = f"set system.main.{option}='/usr/bin/thing'"

    result = change_classes.classify(batch)

    assert result.high is True
    assert result.high_reasons == ("runs-commands",)


def test_a_firewall_include_section_is_high():
    batch = "set firewall.@include[0].path='/etc/firewall.user'"

    result = change_classes.classify(batch)

    assert result.high is True
    assert result.high_reasons == ("runs-commands",)


def test_the_high_reasons_are_sorted_and_unique():
    batch = "\n".join(
        [
            "set firewall.port=redirect",
            "set uhttpd.main.listen_http='0.0.0.0:80'",
            "set dhcp.main.exec='/usr/bin/thing'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.high_reasons == (
        "internet-exposure",
        "management-access",
        "runs-commands",
    )


# --- odd input ---------------------------------------------------------------


def test_an_empty_batch_is_nothing():
    result = change_classes.classify("")

    assert result.classes == frozenset()
    assert result.grantable is False
    assert result.high is False
    assert result.high_reasons == ()


def test_a_batch_of_comments_only_is_nothing():
    result = change_classes.classify("# just a comment\n\n   \n")

    assert result.classes == frozenset()
    assert result.grantable is False


@pytest.mark.parametrize(
    "batch",
    [
        None,
        42,
        "",
        "   ",
        "\n\n\n",
        "!!!",
        "set",
        "set ",
        "add",
        "add dhcp",
        "add dhcp host extra",
        "set dhcp.=host",
        "set dhcp.host1.name='unclosed",
        "delete",
        "rename",
        "reorder",
        "revert",
        "import dhcp",
        "commit dhcp",
    ],
)
def test_classify_never_raises_on_odd_input(batch):
    result = change_classes.classify(batch)

    assert result.grantable is False


def test_the_grantable_classes_are_the_four_named_ones():
    assert change_classes.GRANTABLE_CLASSES == (
        "dhcp-reservations",
        "dns",
        "hostname",
        "wifi-name-key",
    )


def test_every_grantable_class_has_a_plain_label():
    assert set(change_classes.CLASS_LABELS) == set(
        change_classes.GRANTABLE_CLASSES
    )
    assert change_classes.CLASS_LABELS["dhcp-reservations"] == (
        "DHCP reservations"
    )
    assert change_classes.CLASS_LABELS["dns"] == "DNS settings"
    assert change_classes.CLASS_LABELS["hostname"] == "the router name"
    assert change_classes.CLASS_LABELS["wifi-name-key"] == (
        "Wi-Fi name and password"
    )


@pytest.mark.parametrize("option", ["target", "input", "forward"])
def test_accept_on_an_existing_firewall_section_is_internet_exposure(option):
    batch = f"set firewall.cfg0a1b2c.{option}='ACCEPT'"

    result = change_classes.classify(batch)

    assert result.high is True
    assert "internet-exposure" in result.high_reasons


# ---- a section-level set can retype a section ------
#
# ``set config.name=type`` creates a section, or silently changes the type of
# an existing one.  The batch alone cannot tell which, so a grant covers a
# section-level set only for the creations a grant may make (a DHCP host or
# a local DNS record) and never through the wildcard type.


def test_retyping_a_radio_as_an_interface_is_not_grantable():
    batch = "\n".join(
        [
            "set wireless.radio0=wifi-iface",
            "set wireless.radio0.ssid='newton-test-2g'",
        ]
    )
    result = change_classes.classify(batch)
    assert not result.grantable


def test_the_hostname_wildcard_does_not_cover_creating_a_section():
    batch = "\n".join(
        [
            "set system.ntp=system",
            "set system.ntp.hostname='router'",
        ]
    )
    result = change_classes.classify(batch)
    assert not result.grantable


def test_a_named_dhcp_host_is_still_grantable():
    result = change_classes.classify(DHCP_HOST)
    assert result.grantable
    assert result.classes == frozenset({"dhcp-reservations"})


# --- a later section set keeps the facts of the section ---------


def test_a_list_fact_survives_a_later_section_set():
    """A section-level set does not clear the options of the section.

    ``uci set dhcp.h1=host`` changes the TYPE of the section; the
    options that are on it stay on it.  A batch that adds a value to a
    list and then sets the type of the section still carries that
    value, so the change is not a plain reservation.
    """
    batch = "\n".join(
        [
            "add_list dhcp.h1.dhcp_script='/tmp/evil.sh'",
            "set dhcp.h1=host",
            "set dhcp.h1.ip='10.0.0.5'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.grantable is False
    assert result.high is True
    assert result.high_reasons == ("runs-commands",)


def test_an_unexplained_option_survives_a_later_section_set():
    """The same rule for an option no class explains.

    ``dhcp_option`` is not on any class's list, so the change is not
    grantable, whatever the section's type is.
    """
    batch = "\n".join(
        [
            "add_list dhcp.h1.dhcp_option='6,6.6.6.6'",
            "set dhcp.h1=host",
            "set dhcp.h1.ip='10.0.0.5'",
        ]
    )

    result = change_classes.classify(batch)

    assert result.grantable is False


def test_the_section_set_of_a_section_the_router_holds_is_still_high():
    """The rule holds when the router's own type is the one the batch says.

    A grant waives the owner's yes for a DHCP reservation; a batch that
    smuggles a command option into one is HIGH and no grant covers it.
    """
    batch = "\n".join(
        [
            "add_list dhcp.h1.dhcp_script='/tmp/evil.sh'",
            "set dhcp.h1=host",
        ]
    )

    result = change_classes.classify(batch, types={("dhcp", "h1"): "host"})

    assert result.grantable is False
    assert result.high is True
    assert result.high_reasons == ("runs-commands",)
