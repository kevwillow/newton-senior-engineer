"""the reads a no-install router can answer over its own web API.

ADR-021 point 2 and the lab measurement (lab-r1, OpenWrt 25.12.5,
2026-10-30): a limited rpcd user may read a fixed set of things through
the router's own ``/ubus``.  These tests use the measured answers (see
``noinstall_answers``) and a fake router, so no router is contacted.

What is proved here:

  * the result shape is the one the installed path returns;
  * every read is one fresh session, one read call and no write call;
  * the password never appears in a result, an error or a log;
  * a form the web API cannot read is refused by name, in plain words.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import newton_mcp.envelope as _envelope
import newton_mcp.noinstall_read as noinstall_read
import newton_mcp.redact as _redact
import newton_mcp.server as server
from noinstall_answers import data, answer
from newton_mcp.adapters import openwrt_rpcd as rpcd
from noinstall_fakes import FakeDevice, FakeRouter, factory, password_file


# ---- the fixtures ----------------------------------------------------------


def _device(tmp_path: Path, secret: str = "synthetic-password") -> FakeDevice:
    return FakeDevice(rpcd_password_file=password_file(tmp_path, secret))


def _router(answers=None) -> FakeRouter:
    return FakeRouter(answers or {})


def _sanitised(text: str) -> str:
    """The text the output pipeline leaves behind.

    The read path sanitises every piece of device text before it reaches
    the envelope, so a line that imitates a Newton field (``"data":``,
    ``"source":``) is flagged.  The installed path does the same: the
    expectation is the sanitised text, not the raw one.
    """
    return _envelope.sanitise_text(
        text, redact=_redact.redact_text, line_cap=_envelope.FIELD_CAP
    ).text


def _unflagged(text: str) -> str:
    """The sanitised text with the flag prefixes taken off again."""
    out = []
    for line in text.splitlines():
        if line.startswith(_envelope.FLAG_PREFIX):
            line = line[len(_envelope.FLAG_PREFIX) :]
        out.append(line)
    return "\n".join(out)


# ---- the command grammar ---------------------------------------------------


def test_a_command_the_installed_path_refuses_is_refused_here_too(tmp_path) -> None:
    """The installed path's own grammar comes first, and its message stands."""
    device = _device(tmp_path)
    for command in ("cat /etc/passwd", "uci commit", "uci set x.y=1", "nft"):
        with pytest.raises(server.NewtonError) as caught:
            noinstall_read.read_noinstall(device, command, factory(_router()))
        with pytest.raises(server.NewtonError) as installed:
            server.validate_read(command)
        assert str(caught.value) == str(installed.value), command


def test_a_command_with_shell_syntax_is_refused(tmp_path) -> None:
    device = _device(tmp_path)
    with pytest.raises(server.NewtonError) as caught:
        noinstall_read.read_noinstall(device, "uci show; rm -rf /", factory(_router()))
    assert "forbidden shell syntax" in str(caught.value)


# ---- uci -------------------------------------------------------------------


def test_uci_show_of_a_config_prints_the_whole_config(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("uci", "get"): data("uci.get.system")})
    result = noinstall_read.read_noinstall(device, "uci show system", factory(router))
    assert result["exit_code"] == 0
    assert result["stdout"]["text"] == (
        "system.cfg01e48a=system\n"
        "system.cfg01e48a.hostname='lab-r1'\n"
        "system.cfg01e48a.log_size='128'\n"
        "system.cfg01e48a.timezone='GMT0'\n"
        "system.cfg01e48a.ttylogin='0'\n"
        "system.cfg01e48a.urandom_seed='0'\n"
        "system.cfg01e48a.zonename='UTC'\n"
        "system.ntp=timeserver\n"
        "system.ntp.enable_server='0'\n"
        "system.ntp.enabled='1'\n"
        "system.ntp.server='0.openwrt.pool.ntp.org' '1.openwrt.pool.ntp.org' "
        "'2.openwrt.pool.ntp.org' '3.openwrt.pool.ntp.org'\n"
    )
    assert router.calls_of("uci", "get") == [{"config": "system"}]


def test_uci_show_of_the_measured_dhcp_config_prints_every_section(tmp_path) -> None:
    """The whole measured config, section by section, in the index order."""
    device = _device(tmp_path)
    router = _router({("uci", "get"): data("uci.get.dhcp")})
    result = noinstall_read.read_noinstall(device, "uci show dhcp", factory(router))
    assert result["stdout"]["text"] == (
        "dhcp.cfg01411c=dnsmasq\n"
        "dhcp.cfg01411c.authoritative='1'\n"
        "dhcp.cfg01411c.boguspriv='1'\n"
        "dhcp.cfg01411c.cachesize='1000'\n"
        "dhcp.cfg01411c.domain='lan'\n"
        "dhcp.cfg01411c.domainneeded='1'\n"
        "dhcp.cfg01411c.ednspacket_max='1232'\n"
        "dhcp.cfg01411c.expandhosts='1'\n"
        "dhcp.cfg01411c.filter_a='0'\n"
        "dhcp.cfg01411c.filter_aaaa='0'\n"
        "dhcp.cfg01411c.filterwin2k='0'\n"
        "dhcp.cfg01411c.leasefile='/tmp/dhcp.leases'\n"
        "dhcp.cfg01411c.local='/lan/'\n"
        "dhcp.cfg01411c.localise_queries='1'\n"
        "dhcp.cfg01411c.localservice='1'\n"
        "dhcp.cfg01411c.nonegcache='0'\n"
        "dhcp.cfg01411c.nonwildcard='1'\n"
        "dhcp.cfg01411c.readethers='1'\n"
        "dhcp.cfg01411c.rebind_localhost='1'\n"
        "dhcp.cfg01411c.rebind_protection='1'\n"
        "dhcp.cfg01411c.resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'\n"
        "dhcp.lan=dhcp\n"
        "dhcp.lan.dhcpv4='server'\n"
        "dhcp.lan.dhcpv6='server'\n"
        "dhcp.lan.ignore='1'\n"
        "dhcp.lan.interface='lan'\n"
        "dhcp.lan.leasetime='12h'\n"
        "dhcp.lan.limit='150'\n"
        "dhcp.lan.ra='server'\n"
        "dhcp.lan.ra_flags='managed-config' 'other-config'\n"
        "dhcp.lan.ra_slaac='1'\n"
        "dhcp.lan.start='100'\n"
        "dhcp.wan=dhcp\n"
        "dhcp.wan.ignore='1'\n"
        "dhcp.wan.interface='wan'\n"
        "dhcp.odhcpd=odhcpd\n"
        "dhcp.odhcpd.hostsdir='/tmp/hosts'\n"
        "dhcp.odhcpd.leasefile='/tmp/odhcpd.leases'\n"
        "dhcp.odhcpd.leasetrigger='/usr/sbin/odhcpd-update'\n"
        "dhcp.odhcpd.loglevel='4'\n"
        "dhcp.odhcpd.maindhcp='0'\n"
        "dhcp.odhcpd.piodir='/tmp/odhcpd-piodir'\n"
        "dhcp.lab=dhcp\n"
        "dhcp.lab.interface='lab'\n"
        "dhcp.lab.leasetime='12h'\n"
        "dhcp.lab.limit='100'\n"
        "dhcp.lab.start='100'\n"
    )


def test_uci_show_prints_the_sections_in_index_order(tmp_path) -> None:
    """The router's answer lists the sections in any order; uci's is the index."""
    device = _device(tmp_path)
    router = _router({("uci", "get"): data("uci.get.dhcp")})
    result = noinstall_read.read_noinstall(device, "uci show dhcp", factory(router))
    headers = [
        line
        for line in result["stdout"]["text"].splitlines()
        if "=" in line and line.split("=", 1)[0].count(".") == 1
    ]
    assert headers == [
        "dhcp.cfg01411c=dnsmasq",
        "dhcp.lan=dhcp",
        "dhcp.wan=dhcp",
        "dhcp.odhcpd=odhcpd",
        "dhcp.lab=dhcp",
    ]


def test_uci_show_of_a_section_prints_that_section(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("uci", "get"): data("uci.get.network.lan")})
    result = noinstall_read.read_noinstall(device, "uci show network.lan", factory(router))
    assert result["stdout"]["text"] == (
        "network.lan=interface\n"
        "network.lan.device='br-lan'\n"
        "network.lan.ip6assign='60'\n"
        "network.lan.ipaddr='10.109.0.11'\n"
        "network.lan.netmask='255.255.255.0'\n"
        "network.lan.proto='static'\n"
    )
    assert router.calls_of("uci", "get") == [
        {"config": "network", "section": "lan"}
    ]


def test_uci_show_of_one_option_prints_that_option(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("uci", "get"): data("uci.get.network.lan.proto")})
    result = noinstall_read.read_noinstall(
        device, "uci show network.lan.proto", factory(router)
    )
    assert result["stdout"]["text"] == "network.lan.proto='static'\n"
    assert router.calls_of("uci", "get") == [
        {"config": "network", "section": "lan", "option": "proto"}
    ]


def test_uci_get_prints_the_bare_value(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("uci", "get"): data("uci.get.network.lan.proto")})
    result = noinstall_read.read_noinstall(
        device, "uci get network.lan.proto", factory(router)
    )
    assert result["stdout"]["text"] == "static\n"
    assert result["exit_code"] == 0


def test_uci_get_of_an_addressed_section_sends_the_section_verbatim(tmp_path) -> None:
    """The router takes an ``@type[index]`` section as it is.

    The second lab run measured it: rpcd's ``uci get`` answers
    ``system.@system[0].hostname`` with the hostname, and the section
    travels to the router unchanged.
    """
    device = _device(tmp_path)
    router = _router({("uci", "get"): data("uci.get.system.atsection.hostname")})
    result = noinstall_read.read_noinstall(
        device, "uci get system.@system[0].hostname", factory(router)
    )
    assert result["exit_code"] == 0
    assert result["stdout"]["text"] == "lab-r1\n"
    assert router.calls_of("uci", "get") == [
        {"config": "system", "section": "@system[0]", "option": "hostname"}
    ]


def test_an_index_that_is_out_of_range_is_not_found(tmp_path) -> None:
    """The measured answer of an index that is not there: ``[0]``."""
    device = _device(tmp_path)
    router = _router({("uci", "get"): data("uci.get.dhcp.atsection.outofrange")})
    result = noinstall_read.read_noinstall(
        device, "uci get dhcp.@dnsmasq[7].domain", factory(router)
    )
    assert result["exit_code"] == 1
    assert result["stderr"]["text"] == "uci: Entry not found\n"


def _section_answer(config_key: str, section: str) -> dict:
    """The answer for a named section, taken from the measured config answer.

    The router answers a named section with that section's own fields
    (the measured ``uci get network.lan``), not with a map of sections.
    """
    return {"values": dict(data(config_key)["values"][section])}


def test_a_list_option_is_printed_the_way_uci_prints_it(tmp_path) -> None:
    """A list is printed as uci prints it: one quoted word per element."""
    device = _device(tmp_path)
    router = _router({("uci", "get"): _section_answer("uci.get.dhcp", "lan")})
    result = noinstall_read.read_noinstall(device, "uci show dhcp.lan", factory(router))
    assert result["stdout"]["text"] == (
        "dhcp.lan=dhcp\n"
        "dhcp.lan.dhcpv4='server'\n"
        "dhcp.lan.dhcpv6='server'\n"
        "dhcp.lan.ignore='1'\n"
        "dhcp.lan.interface='lan'\n"
        "dhcp.lan.leasetime='12h'\n"
        "dhcp.lan.limit='150'\n"
        "dhcp.lan.ra='server'\n"
        "dhcp.lan.ra_flags='managed-config' 'other-config'\n"
        "dhcp.lan.ra_slaac='1'\n"
        "dhcp.lan.start='100'\n"
    )


def test_a_value_with_a_quote_is_escaped_the_way_uci_escapes_it(tmp_path) -> None:
    """A quote inside a value is escaped the way uci escapes it.

    The measured answers carry no quote in a value, so the option is
    added to a measured section; the escaping is the part under test.
    """
    device = _device(tmp_path)
    section = dict(data("uci.get.network.lan")["values"])
    section["note"] = "it's here"
    router = _router({("uci", "get"): {"values": section}})
    result = noinstall_read.read_noinstall(device, "uci show network.lan", factory(router))
    assert result["stdout"]["text"] == (
        "network.lan=interface\n"
        "network.lan.device='br-lan'\n"
        "network.lan.ip6assign='60'\n"
        "network.lan.ipaddr='10.109.0.11'\n"
        "network.lan.netmask='255.255.255.0'\n"
        "network.lan.proto='static'\n"
        "network.lan.note='it'\\''s here'\n"
    )


def test_a_missing_option_is_an_entry_not_found(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("uci", "get"): answer("uci.get.missing.option")})
    result = noinstall_read.read_noinstall(
        device, "uci get network.lan.nosuchoption", factory(router)
    )
    assert result["exit_code"] == 1
    assert result["stderr"]["text"] == "uci: Entry not found\n"
    assert result["stdout"]["text"] == ""


def test_a_missing_section_is_an_entry_not_found(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("uci", "get"): answer("uci.get.missing.section")})
    result = noinstall_read.read_noinstall(
        device, "uci show network.nosuchsection", factory(router)
    )
    assert result["exit_code"] == 1
    assert result["stderr"]["text"] == "uci: Entry not found\n"


def test_a_uci_get_of_a_whole_section_is_refused(tmp_path) -> None:
    """``uci get`` of a section has no bare value; ``uci show`` has it."""
    device = _device(tmp_path)
    router = _router({("uci", "get"): data("uci.get.network.lan")})
    with pytest.raises(server.NewtonError) as caught:
        noinstall_read.read_noinstall(
            device, "uci get network.lan", factory(router)
        )
    assert str(caught.value) == (
        "uci get of a section is not available in no-install access; the "
        "router's web API cannot read it. Installed access can."
    )
    assert router.calls == [], "a refused read must not reach the router"


def test_a_config_the_router_has_not_got_is_an_entry_not_found(tmp_path) -> None:
    """A router without a radio answers [4]: uci says the entry is not found."""
    device = _device(tmp_path)
    router = _router({("uci", "get"): 4})
    result = noinstall_read.read_noinstall(device, "uci show wireless", factory(router))
    assert result["exit_code"] == 1
    assert result["stderr"]["text"] == "uci: Entry not found\n"


def test_a_config_outside_the_readable_list_is_refused_without_a_call(tmp_path) -> None:
    """The router answers [6] for an unknown config: the read is refused first."""
    device = _device(tmp_path)
    router = _router({("uci", "get"): 6})
    with pytest.raises(server.NewtonError) as caught:
        noinstall_read.read_noinstall(device, "uci show rpcd", factory(router))
    assert str(caught.value) == (
        "uci show rpcd is not readable in no-install access; the router's web "
        "API cannot read that config. Installed access can."
    )
    assert router.calls == [], "a refused read must not reach the router"


def test_uci_show_without_a_config_is_refused(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router()
    with pytest.raises(server.NewtonError) as caught:
        noinstall_read.read_noinstall(device, "uci show", factory(router))
    assert "name a config" in str(caught.value)
    assert router.calls == []


def test_uci_export_and_uci_changes_are_refused(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router()
    for command, form in (("uci export", "uci export"), ("uci changes", "uci changes")):
        with pytest.raises(server.NewtonError) as caught:
            noinstall_read.read_noinstall(device, command, factory(router))
        assert str(caught.value) == (
            f"{form} is not available in no-install access; the router's web "
            "API cannot read it. Installed access can."
        )
    assert router.calls == []


# ---- ubus ------------------------------------------------------------------


def test_the_ubus_status_reads_print_json(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("system", "board"): data("system.board")})
    result = noinstall_read.read_noinstall(
        device, "ubus call system board", factory(router)
    )
    assert result["exit_code"] == 0
    assert json.loads(result["stdout"]["text"]) == data("system.board")
    assert result["stdout"]["text"] == json.dumps(
        data("system.board"), indent="\t"
    ) + "\n"
    assert router.calls_of("system", "board") == [{}]


def test_the_interface_dump_prints_json(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("network.interface", "dump"): data("network.interface.dump")})
    result = noinstall_read.read_noinstall(
        device, "ubus call network.interface dump", factory(router)
    )
    raw = json.dumps(data("network.interface.dump"), indent="\t") + "\n"
    assert result["stdout"]["text"] == _sanitised(raw)
    assert json.loads(_unflagged(result["stdout"]["text"])) == data(
        "network.interface.dump"
    )


def test_one_interface_status_is_picked_out_of_the_dump(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("network.interface", "dump"): data("network.interface.dump")})
    result = noinstall_read.read_noinstall(
        device, "ubus call network.interface.lan status", factory(router)
    )
    picked = json.loads(_unflagged(result["stdout"]["text"]))
    assert picked["interface"] == "lan"
    assert picked["up"] is True
    assert len(picked) == len(data("network.interface.dump")["interface"][0])
    assert router.calls_of("network.interface", "dump") == [{}]


def test_an_interface_that_is_not_there_is_not_found(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("network.interface", "dump"): data("network.interface.dump")})
    result = noinstall_read.read_noinstall(
        device, "ubus call network.interface.nosuch status", factory(router)
    )
    assert result["exit_code"] == 4
    assert result["stderr"]["text"] == "Command failed: Not found\n"


def test_the_wireless_status_is_refused(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router()
    with pytest.raises(server.NewtonError) as caught:
        noinstall_read.read_noinstall(
            device, "ubus call network.wireless status", factory(router)
        )
    assert str(caught.value) == (
        "ubus call network.wireless status is not available in no-install "
        "access; the router's web API cannot read it. Installed access can."
    )
    assert router.calls == []


# ---- logread ---------------------------------------------------------------


def test_logread_asks_for_a_stream_that_is_not_streaming(tmp_path) -> None:
    """Without stream=false the router answers empty: the flag is required."""
    device = _device(tmp_path)
    router = _router({("log", "read"): data("log.read")})
    result = noinstall_read.read_noinstall(device, "logread", factory(router))
    assert router.calls_of("log", "read") == [{"lines": 100, "stream": False}]
    assert result["exit_code"] == 0


def test_logread_prints_one_line_per_entry(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("log", "read"): data("log.read")})
    result = noinstall_read.read_noinstall(device, "logread -l 3", factory(router))
    assert router.calls_of("log", "read") == [{"lines": 3, "stream": False}]
    lines = result["stdout"]["text"].splitlines()
    assert len(lines) == 3
    assert lines[0].startswith("dropbear[3242]: Pubkey auth succeeded")
    assert all("priority" not in line for line in lines)


def test_logread_with_a_pattern_keeps_only_the_matching_lines(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("log", "read"): data("log.read")})
    result = noinstall_read.read_noinstall(
        device, "logread -e odhcpd -l 3", factory(router)
    )
    lines = result["stdout"]["text"].splitlines()
    assert len(lines) == 1
    assert "odhcpd" in lines[0]


# ---- the leases ------------------------------------------------------------


def test_the_dhcp_leases_are_printed_as_lease_file_lines(tmp_path) -> None:
    """The lease file's line order is dnsmasq's; the fields are the answer's."""
    device = _device(tmp_path)
    router = _router(
        {
            ("luci-rpc", "getDHCPLeases"): {
                "dhcp_leases": [
                    {
                        "expires": 1793399999,
                        "mac": "02:00:00:00:10:01",
                        "ip": "10.109.0.11",
                        "hostname": "lab-r1.lan",
                        "clientid": "01:02:00:00:00:10:01",
                    },
                    {"expires": 1793399998, "mac": "02:00:00:00:10:03", "ip": "10.101.0.110"},
                ],
                "dhcp6_leases": [],
            }
        },
    )
    result = noinstall_read.read_noinstall(
        device, "cat /tmp/dhcp.leases", factory(router)
    )
    assert result["stdout"]["text"] == (
        "1793399999 02:00:00:00:10:01 10.109.0.11 lab-r1.lan 01:02:00:00:00:10:01\n"
        "1793399998 02:00:00:00:10:03 10.101.0.110 * *\n"
    )
    assert router.calls_of("luci-rpc", "getDHCPLeases") == [{}]


# ---- iwinfo ----------------------------------------------------------------


def test_iwinfo_prints_json(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("iwinfo", "assoclist"): {"radio0": []}})
    result = noinstall_read.read_noinstall(
        device, "iwinfo wlan0 assoclist", factory(router)
    )
    assert result["exit_code"] == 0
    assert json.loads(result["stdout"]["text"]) == {"radio0": []}
    assert router.calls_of("iwinfo", "assoclist") == [{"device": "wlan0"}]


def test_iwinfo_on_a_router_without_a_radio_is_refused(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("iwinfo", "assoclist"): 4})
    result = noinstall_read.read_noinstall(
        device, "iwinfo wlan0 assoclist", factory(router)
    )
    assert result["exit_code"] == 1
    assert result["stderr"]["text"] == "No such wireless device\n"


def test_iwinfo_without_a_device_is_refused(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router()
    for command in ("iwinfo", "iwinfo wlan0 info", "iwinfo wlan0 htmodelist"):
        with pytest.raises(server.NewtonError) as caught:
            noinstall_read.read_noinstall(device, command, factory(router))
        assert "is not available in no-install access" in str(caught.value), command
    assert router.calls == []


# ---- ping, traceroute, nslookup --------------------------------------------


def test_ping_uses_the_binary_the_image_has(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("file", "exec"): data("file.exec.ping")})
    result = noinstall_read.read_noinstall(
        device, "ping -c 1 127.0.0.1", factory(router)
    )
    assert router.calls_of("file", "exec") == [
        {
            "command": "/bin/ping",
            "params": ["-c", "1", "-W", "2", "127.0.0.1"],
        }
    ]
    assert result["exit_code"] == 0
    assert result["stdout"]["text"] == data("file.exec.ping")["stdout"]


def test_a_failing_ping_reports_the_exit_code(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("file", "exec"): data("file.exec.ping.fail")})
    result = noinstall_read.read_noinstall(
        device, "ping -c 1 198.51.100.1", factory(router)
    )
    assert result["exit_code"] == 1
    assert "100% packet loss" in result["stdout"]["text"]


def test_traceroute_and_nslookup_use_their_own_binaries(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("file", "exec"): data("file.exec.nslookup")})
    noinstall_read.read_noinstall(device, "traceroute 127.0.0.1", factory(router))
    assert router.calls_of("file", "exec") == [
        {"command": "/bin/traceroute", "params": ["-w", "2", "127.0.0.1"]}
    ]
    router.calls.clear()
    noinstall_read.read_noinstall(
        device, "nslookup localhost 127.0.0.1", factory(router)
    )
    assert router.calls_of("file", "exec") == [
        {
            "command": "/usr/bin/nslookup",
            "params": ["localhost", "127.0.0.1"],
        }
    ]


# ---- the reads that need installed access ----------------------------------


def test_the_system_reads_are_refused_with_the_system_info_hint(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router()
    for command, form in (
        ("uptime", "uptime"),
        ("free", "free"),
        ("cat /proc/uptime", "cat /proc/uptime"),
        ("cat /proc/loadavg", "cat /proc/loadavg"),
        ("cat /proc/meminfo", "cat /proc/meminfo"),
    ):
        with pytest.raises(server.NewtonError) as caught:
            noinstall_read.read_noinstall(device, command, factory(router))
        assert str(caught.value) == (
            f"{form} is not available in no-install access; the router's web "
            "API cannot read it. Installed access can. Use `ubus call system "
            "info` for the same information."
        ), command
    assert router.calls == []


def test_every_other_read_form_is_refused_by_name(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router()
    refused = [
        ("ubus list", "ubus list"),
        ("wifi status", "wifi status"),
        ("ifstatus lan", "ifstatus"),
        ("nft list ruleset", "nft"),
        ("fw4 check", "fw4"),
        ("ip addr show", "ip"),
        ("netstat -t", "netstat"),
        ("df -h", "df"),
        ("uname -a", "uname"),
        ("apk list", "apk"),
        ("cat /etc/openwrt_release", "cat /etc/openwrt_release"),
        ("cat /etc/config/network", "cat /etc/config/network"),
        ("wifiscan radio0", "wifiscan"),
    ]
    for command, form in refused:
        with pytest.raises(server.NewtonError) as caught:
            noinstall_read.read_noinstall(device, command, factory(router))
        assert str(caught.value) == (
            f"{form} is not available in no-install access; the router's web "
            "API cannot read it. Installed access can."
        ), command
    assert router.calls == []


# ---- the shape of the result, and the rules around it ----------------------


def test_the_result_has_the_shape_the_installed_path_returns(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("system", "board"): data("system.board")})
    result = noinstall_read.read_noinstall(
        device, "ubus call system board", factory(router)
    )
    assert set(result) == {"exit_code", "stdout", "stderr", "truncated"}
    assert result["stdout"]["kind"] == "untrusted-device-data"
    assert result["stdout"]["source"] == "lab-r1:ubus call system board"
    assert result["stderr"]["kind"] == "untrusted-device-data"
    assert result["stderr"]["source"] == "lab-r1:ubus call system board"
    assert result["truncated"] is False


def test_every_read_opens_its_own_session(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router({("system", "board"): data("system.board")})
    for _ in range(2):
        noinstall_read.read_noinstall(device, "ubus call system board", factory(router))
    assert len(router.logins) == 2
    assert router.logins[0][0] == "newton"
    assert router.logins[0][2] == 30


def test_a_read_never_makes_a_write_call(tmp_path) -> None:
    device = _device(tmp_path)
    router = _router(
        {
            ("uci", "get"): data("uci.get.system"),
            ("system", "info"): data("system.info"),
            ("log", "read"): data("log.read"),
            ("service", "list"): data("service.list.dnsmasq"),
        }
    )
    for command in (
        "uci show system",
        "ubus call system info",
        "logread -l 3",
    ):
        noinstall_read.read_noinstall(device, command, factory(router))
    forbidden = {"set", "add", "delete", "apply", "confirm", "commit", "revert"}
    assert router.calls
    for _sid, _obj, fn, _args in router.calls:
        assert fn not in forbidden, fn


def test_the_password_never_appears_in_the_result(tmp_path) -> None:
    secret = "correct-horse-battery-staple"
    device = _device(tmp_path, secret)
    router = _router({("system", "board"): data("system.board")})
    result = noinstall_read.read_noinstall(
        device, "ubus call system board", factory(router)
    )
    assert secret not in json.dumps(result)
    assert secret not in repr(result)


def test_the_password_never_appears_in_an_error(tmp_path) -> None:
    """A failure that reaches the model says nothing about the secret."""
    secret = "correct-horse-battery-staple"
    device = _device(tmp_path, secret)
    router = _router({("system", "board"): rpcd_transport_error()})
    result = noinstall_read.read_noinstall(
        device, "ubus call system board", factory(router)
    )
    assert secret not in json.dumps(result)
    assert secret not in repr(result)
    assert result["exit_code"] == 1


def test_a_refused_login_says_nothing_about_the_password(tmp_path) -> None:
    secret = "correct-horse-battery-staple"
    device = _device(tmp_path, secret)

    class RefusesLogin(FakeRouter):
        def login(self, username, password, timeout_s):
            raise rpcd_transport_error()

    with pytest.raises(server.NewtonError) as caught:
        noinstall_read.read_noinstall(
            device, "ubus call system board", factory(RefusesLogin())
        )
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)
    assert "could not be reached" in str(caught.value)


def rpcd_transport_error():
    from newton_mcp.adapters.openwrt_rpcd import RpcdTransportError

    return RpcdTransportError("the router could not be reached", sent=True)


def test_the_read_path_never_reaches_ssh(tmp_path, monkeypatch) -> None:
    """A no-install read goes to the web API and to nothing else."""
    password = password_file(tmp_path)
    inventory = tmp_path / "devices.toml"
    inventory.write_text(
        '[devices.lab-r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
        'access = "no-install"\n'
        f'rpcd_password_file = "{password}"\n'
        'https_spki = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="\n',
        encoding="utf-8",
    )
    inventory.chmod(0o644)
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))

    import subprocess

    from newton_mcp import ssh_path

    def refuse(*args, **kwargs):
        raise AssertionError("a no-install read must not reach ssh")

    # the real function is cached; the fake keeps its cache_clear so the
    # inventory reset in the fixture does not break.
    refuse.cache_clear = ssh_path.resolve_ssh.cache_clear
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(ssh_path, "resolve_ssh", refuse)

    router = FakeRouter({("system", "board"): data("system.board")})
    service = server.NewtonService()
    device = service.devices["lab-r1"]
    result = noinstall_read.read_noinstall(
        device, "ubus call system board", factory(router)
    )
    assert result["exit_code"] == 0
