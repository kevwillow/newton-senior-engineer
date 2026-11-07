"""Leash classification corpus: a committed base config and ~150 scenarios with hand-written expectations.

Copied from a reference check: `base_config`, `Z`,
the `sc_(name, ops, expect, profile, zones, may)` writer, the `SCENARIOS` list and the `MAY`
map of extra codes a real uci may emit in `index` mode (empty in `id` mode). `SCENARIO_IDS` is
added for pytest parametrisation.
"""
from leash_model import Scenario, Sec


def base_config():
    S = Sec
    return {
        "network": [
            S("interface", "loopback", proto="static", device="lo"),
            S("interface", "lan", proto="static", ipaddr="192.168.1.1", device="br-lan"),
            S("interface", "wan", proto="dhcp", device="eth1"),
            S("interface", "wan6", proto="dhcpv6", device="eth1"),
            S("interface", "guest", proto="static", ipaddr="192.168.5.1"),
            S("device", None, name="br-lan", type="bridge", ports=["lan1", "lan2"]),
            S("route", "r1", interface="wan", target="10.9.0.0/16", gateway="10.0.0.1"),
        ],
        "firewall": [
            S("defaults", None, input="REJECT", output="ACCEPT", forward="REJECT", synflood_protect="1"),
            S("zone", None, name="lan", network=["lan"], input="ACCEPT", output="ACCEPT", forward="ACCEPT"),
            S("zone", None, name="wan", network=["wan", "wan6"], input="REJECT", output="ACCEPT", forward="REJECT", masq="1", mtu_fix="1"),
            S("zone", None, name="guest", network=["guest"], input="REJECT", output="ACCEPT", forward="REJECT"),
            S("zone", None, network=["nameless"], input="REJECT", output="ACCEPT", forward="REJECT"),
            S("zone", None, name="mgmt2", network=["lan"], input="REJECT", output="ACCEPT", forward="REJECT"),
            S("forwarding", None, src="lan", dest="wan"),
            S("forwarding", None, src="guest", dest="wan"),
            S("rule", None, name="Allow-DHCP-Renew", src="wan", proto="udp", dest_port="68", target="ACCEPT", family="ipv4"),
            S("rule", None, name="Allow-Ping", src="wan", proto="icmp", target="ACCEPT"),
            S("rule", None, name="Block-X", src="wan", proto="tcp", dest_port="23", target="REJECT"),
            S("rule", None, name="Out-Rule", proto="tcp", dest_port="25", target="REJECT"),
            S("rule", None, name="Lan-Rule", src="lan", proto="tcp", dest_port="80", target="ACCEPT"),
            S("redirect", None, name="ssh-fwd", src="lan", dest="guest", src_dport="2222", dest_port="22"),
            S("include", None, path="/etc/firewall.user"),
        ],
        "dhcp": [
            S("dnsmasq", None, domainneeded="1", boguspriv="1", foo="bar"),
            S("dhcp", "lan", interface="lan", start="100", limit="150"),
        ],
        "system": [
            S("system", None, hostname="OpenWrt", timezone="UTC"),
            S("timeserver", "ntp", enabled="1", enable_server="0", server=["0.openwrt.pool.ntp.org"]),
        ],
        "dropbear": [S("dropbear", None, PasswordAuth="on", Port="22")],
        "rpcd": [S("login", None, username="root", password="$p$root")],
        "uhttpd": [S("uhttpd", "main", listen_http="0.0.0.0:80", listen_https="0.0.0.0:443")],
        "upnpd": [S("upnpd", "config", enabled="0", enable_upnp="1", enable_natpmp="1")],
        "wireless": [S("wifi-device", "radio0", channel="auto"), S("wifi-iface", None, device="radio0", ssid="home", key="secretkey")],
        "ucitrack": [S("network", None, init="network")],
    }


def Z(tok_type, idx):
    return f"@{tok_type}[{idx}]"


S = Sec
SCENARIOS = []


MAY = {}


def sc_(name, ops, expect, profile="lab", zones=None, may=()):
    SCENARIOS.append((name, ops, set(expect), profile, zones))
    MAY[name] = set(may)


# ---- hand-written scenarios with hand-written expectations (design 5.2) ------------------------------------------------
sc_("hostname", [("set", "system", "@system[0]", "hostname", "R2")], [])
sc_("dnsmasq domainneeded", [("set", "dhcp", "@dnsmasq[0]", "domainneeded", "0")], [])
sc_("dropbear port", [("set", "dropbear", "@dropbear[0]", "Port", "2222")], ["mgmt-config"])
sc_("uhttpd listen", [("set", "uhttpd", "main", "listen_https", "0.0.0.0:8443")], ["mgmt-config"])
sc_("rpcd login", [("set", "rpcd", "@login[0]", "username", "x")], ["mgmt-config"])
sc_("lan ipaddr", [("set", "network", "lan", "ipaddr", "192.168.9.1")], ["mgmt-interface"])
sc_("lan new option", [("set", "network", "lan", "mtu", "1400")], ["mgmt-interface"])
sc_("wan proto", [("set", "network", "wan", "proto", "static")], [])
sc_("guest ipaddr", [("set", "network", "guest", "ipaddr", "192.168.6.1")], [])
sc_("rename mgmt interface", [("renamesec", "network", "lan", "lan2")], ["mgmt-interface"])
sc_("rename a non-mgmt interface", [("renamesec", "network", "guest", "guest2")], [])
sc_("rename custom mgmt interface", [("renamesec", "network", "guest", "guest2")], ["mgmt-interface"], zones={"mgmt-interface": "guest", "mgmt-zone": "lan", "wan-zone": ["wan"]})
sc_("bridge ports", [("addlist", "network", "@device[0]", "ports", "lan3")], ["bridge-member"])
sc_("new bridge-vlan", [("newsec", "network", S("bridge-vlan", None, device="br-lan", vlan="10"), "vlan10")], ["bridge-member"])
sc_("lan zone input", [("set", "firewall", "@zone[0]", "input", "ACCEPT")], ["mgmt-zone"])
sc_("lan zone forward", [("set", "firewall", "@zone[0]", "forward", "REJECT")], ["mgmt-zone"])
sc_("lan zone network", [("addlist", "firewall", "@zone[0]", "network", "guest")], ["mgmt-zone"])
sc_("lan zone masq", [("set", "firewall", "@zone[0]", "masq", "1")], ["mgmt-zone"])
sc_("lan zone delete", [("delsec", "firewall", "@zone[0]")], ["mgmt-zone"], may=["wan-zone"])
sc_("lan zone rename", [("renamesec", "firewall", "@zone[0]", "lanzone")], ["mgmt-zone"])
sc_("lan zone reorder", [("reorder", "firewall", "@zone[0]", 3)], ["mgmt-zone"])
sc_("mgmt2 zone found by network", [("set", "firewall", "@zone[4]", "input", "ACCEPT")], ["mgmt-zone"])
sc_("new zone named lan", [("newsec", "firewall", S("zone", None, name="lan", network=["x"], input="REJECT", output="ACCEPT", forward="REJECT"), "newlan")], ["mgmt-zone"])
sc_("new zone network lan", [("newsec", "firewall", S("zone", None, name="z9", network=["lan"], input="REJECT", output="ACCEPT", forward="REJECT"), "z9")], ["mgmt-zone"])
sc_("wan input ACCEPT", [("set", "firewall", "@zone[1]", "input", "ACCEPT")], ["wan-zone"])
sc_("wan input REJECT", [("set", "firewall", "@zone[1]", "input", "REJECT")], [])
sc_("wan input drop lower", [("set", "firewall", "@zone[1]", "input", "drop")], [])
sc_("wan forward reject lower", [("set", "firewall", "@zone[1]", "forward", "reject")], [])
sc_("wan forward ACCEPT lower", [("set", "firewall", "@zone[1]", "forward", "accept")], ["wan-zone"])
for opt in ("output", "log", "log_limit", "mtu_fix", "masq", "masq6"):
    sc_(f"wan {opt}", [("set", "firewall", "@zone[1]", opt, "0" if opt != "log_limit" else "10/minute")], [])
sc_("wan network add", [("addlist", "firewall", "@zone[1]", "network", "guest")], ["wan-zone"])
sc_("wan device", [("set", "firewall", "@zone[1]", "device", "eth9")], ["wan-zone"])
sc_("wan subnet", [("set", "firewall", "@zone[1]", "subnet", "10.0.0.0/8")], ["wan-zone", "path-option"][:1] if False else ["wan-zone"])
sc_("wan extra", [("set", "firewall", "@zone[1]", "extra", "x")], ["wan-zone"])
sc_("wan extra_src", [("set", "firewall", "@zone[1]", "extra_src", "x")], ["wan-zone"])
sc_("wan extra_dest", [("set", "firewall", "@zone[1]", "extra_dest", "x")], ["wan-zone"])
sc_("wan family", [("set", "firewall", "@zone[1]", "family", "ipv4")], ["wan-zone"])
sc_("wan input deleted", [("delopt", "firewall", "@zone[1]", "input")], ["wan-zone"])
sc_("wan forward deleted", [("delopt", "firewall", "@zone[1]", "forward")], ["wan-zone"])
sc_("wan name", [("set", "firewall", "@zone[1]", "name", "wan2")], ["wan-zone"])
sc_("wan delete", [("delsec", "firewall", "@zone[1]")], ["wan-zone"])
sc_("wan rename", [("renamesec", "firewall", "@zone[1]", "wanzone")], ["wan-zone"])
sc_("wan reorder", [("reorder", "firewall", "@zone[1]", 0)], ["wan-zone"])
sc_("wan input REJECT and masq", [("set", "firewall", "@zone[1]", "input", "REJECT"), ("set", "firewall", "@zone[1]", "masq", "0")], [])
sc_("wan input REJECT and device", [("set", "firewall", "@zone[1]", "input", "REJECT"), ("set", "firewall", "@zone[1]", "device", "x")], ["wan-zone"])
sc_("new zone ok", [("newsec", "firewall", S("zone", None, name="iot", network=["iot"], input="REJECT", output="ACCEPT", forward="REJECT"), "iot")], [])
sc_("new zone input ACCEPT", [("newsec", "firewall", S("zone", None, name="iot", network=["iot"], input="ACCEPT", output="ACCEPT", forward="REJECT"), "iot")], ["zone-exposure"])
sc_("new zone forward accept lower", [("newsec", "firewall", S("zone", None, name="iot", network=["iot"], input="REJECT", output="ACCEPT", forward="accept"), "iot")], ["zone-exposure"])
sc_("new zone no forward", [("newsec", "firewall", S("zone", None, name="iot", network=["iot"], input="REJECT", output="ACCEPT"), "iot")], ["zone-exposure"])
sc_("new zone no input", [("newsec", "firewall", S("zone", None, name="iot", network=["iot"], forward="REJECT", output="ACCEPT"), "iot")], ["zone-exposure"])
sc_("new zone network wan", [("newsec", "firewall", S("zone", None, name="iot", network=["iot", "wan"], input="REJECT", output="ACCEPT", forward="REJECT"), "iot")], ["zone-exposure"])
sc_("new zone network wan6", [("newsec", "firewall", S("zone", None, name="iot", network=["wan6"], input="REJECT", output="ACCEPT", forward="REJECT"), "iot")], ["zone-exposure"])
sc_("new zone device", [("newsec", "firewall", S("zone", None, name="iot", device=["eth9"], input="REJECT", output="ACCEPT", forward="REJECT"), "iot")], ["zone-exposure"])
sc_("new zone subnet", [("newsec", "firewall", S("zone", None, name="iot", subnet=["10.0.0.0/8"], input="REJECT", output="ACCEPT", forward="REJECT"), "iot")], ["zone-exposure", "path-option"][:1])
sc_("new zone extra", [("newsec", "firewall", S("zone", None, name="iot", extra="x", input="REJECT", output="ACCEPT", forward="REJECT"), "iot")], ["zone-exposure"])
sc_("guest input ACCEPT", [("set", "firewall", "@zone[2]", "input", "ACCEPT")], ["zone-exposure"])
sc_("guest forward ACCEPT lower", [("set", "firewall", "@zone[2]", "forward", "accept")], ["zone-exposure"])
sc_("guest input deleted", [("delopt", "firewall", "@zone[2]", "input")], ["zone-exposure"])
sc_("guest forward deleted", [("delopt", "firewall", "@zone[2]", "forward")], ["zone-exposure"])
sc_("guest gains wan", [("addlist", "firewall", "@zone[2]", "network", "wan")], ["zone-exposure"])
sc_("guest gains wan6", [("addlist", "firewall", "@zone[2]", "network", "wan6")], ["zone-exposure"])
sc_("guest gains nothing", [("addlist", "firewall", "@zone[2]", "network", "iot")], [])
sc_("guest device", [("set", "firewall", "@zone[2]", "device", "eth9")], ["zone-exposure"])
sc_("guest family", [("set", "firewall", "@zone[2]", "family", "ipv4")], ["zone-exposure"])
sc_("guest extra_src", [("set", "firewall", "@zone[2]", "extra_src", "x")], ["zone-exposure"])
sc_("guest masq", [("set", "firewall", "@zone[2]", "masq", "1")], [])
sc_("guest input REJECT", [("set", "firewall", "@zone[2]", "input", "DROP")], [])
sc_("guest delete", [("delsec", "firewall", "@zone[2]")], [])
sc_("nameless zone ACCEPT", [("set", "firewall", "@zone[3]", "input", "ACCEPT")], ["section-unidentified", "zone-exposure"])
sc_("nameless zone masq", [("set", "firewall", "@zone[3]", "masq", "1")], ["section-unidentified"])
sc_("zone tab network", [("set", "firewall", "@zone[2]", "network", "guest\twan")], ["zone-exposure"])
sc_("zone double space network", [("set", "firewall", "@zone[2]", "network", "guest  wan")], ["zone-exposure"])
sc_("forwarding lan->guest new", [("newsec", "firewall", S("forwarding", None, src="lan", dest="guest"), "f1")], ["forwarding-mgmt"])
sc_("forwarding guest->lan new", [("newsec", "firewall", S("forwarding", None, src="guest", dest="lan"), "f1")], ["forwarding-mgmt"])
sc_("forwarding guest->wan new", [("newsec", "firewall", S("forwarding", None, src="guest", dest="wan"), "f1")], [])
sc_("forwarding wan->guest new", [("newsec", "firewall", S("forwarding", None, src="wan", dest="guest"), "f1")], ["wan-forwarding"])
sc_("forwarding wan->lan new", [("newsec", "firewall", S("forwarding", None, src="wan", dest="lan"), "f1")], ["forwarding-mgmt", "wan-forwarding"])
sc_("forwarding *", [("newsec", "firewall", S("forwarding", None, src="*", dest="guest"), "f1")], ["wan-forwarding"])
sc_("forwarding lan existing set", [("set", "firewall", "@forwarding[0]", "enabled", "0")], ["forwarding-mgmt"])
sc_("forwarding guest existing set", [("set", "firewall", "@forwarding[1]", "enabled", "0")], [])
sc_("forwarding delete lan", [("delsec", "firewall", "@forwarding[0]")], ["forwarding-mgmt"])
sc_("redirect wan new", [("newsec", "firewall", S("redirect", None, src="wan", dest="lan", src_dport="2222", dest_port="22", target="DNAT"), "r1")], ["wan-redirect"])
sc_("redirect lan new", [("newsec", "firewall", S("redirect", None, src="lan", dest="guest", src_dport="2222", dest_port="22"), "r1")], [])
sc_("redirect star new", [("newsec", "firewall", S("redirect", None, src="*", dest="lan"), "r1")], ["wan-redirect"])
sc_("redirect nosrc new", [("newsec", "firewall", S("redirect", None, dest="lan"), "r1")], ["wan-redirect"])
sc_("redirect existing set", [("set", "firewall", "@redirect[0]", "dest_port", "23")], [])
sc_("rule wan ACCEPT new", [("newsec", "firewall", S("rule", None, name="x", src="wan", proto="tcp", dest_port="22", target="ACCEPT"), "r1")], ["wan-rule"])
sc_("rule wan accept lower new", [("newsec", "firewall", S("rule", None, name="x", src="wan", proto="tcp", dest_port="22", target="accept"), "r1")], ["wan-rule"])
sc_("rule wan REJECT new", [("newsec", "firewall", S("rule", None, name="x", src="wan", proto="tcp", dest_port="22", target="REJECT"), "r1")], [])
sc_("rule wan no target new", [("newsec", "firewall", S("rule", None, name="x", src="wan", proto="tcp", dest_port="22"), "r1")], ["wan-rule"])
sc_("rule star ACCEPT new", [("newsec", "firewall", S("rule", None, name="x", src="*", proto="tcp", dest_port="22", target="ACCEPT"), "r1")], ["wan-rule"])
sc_("rule lan ACCEPT new", [("newsec", "firewall", S("rule", None, name="x", src="lan", proto="tcp", dest_port="22", target="ACCEPT"), "r1")], [])
sc_("rule no src new", [("newsec", "firewall", S("rule", None, name="x", proto="tcp", dest_port="22", target="ACCEPT"), "r1")], [])
sc_("rule wan REJECT deleted", [("delsec", "firewall", "@rule[2]")], ["wan-rule"])
sc_("rule wan REJECT reordered", [("reorder", "firewall", "@rule[2]", 0)], ["wan-rule"])
sc_("rule wan REJECT disabled", [("set", "firewall", "@rule[2]", "enabled", "0")], ["wan-rule"])
sc_("rule wan REJECT other set", [("set", "firewall", "@rule[2]", "dest_port", "24")], [])
sc_("rule wan ACCEPT -> REJECT", [("set", "firewall", "@rule[0]", "target", "REJECT")], [])
sc_("rule wan ACCEPT other set", [("set", "firewall", "@rule[0]", "dest_port", "69")], ["wan-rule"])
sc_("rule out reorder", [("reorder", "firewall", "@rule[3]", 0)], [])
sc_("rule lan deleted", [("delsec", "firewall", "@rule[4]")], [])
sc_("defaults input ACCEPT", [("set", "firewall", "@defaults[0]", "input", "ACCEPT")], ["defaults-accept"])
sc_("defaults forward accept lower", [("set", "firewall", "@defaults[0]", "forward", "accept")], ["defaults-accept"])
sc_("defaults input REJECT", [("set", "firewall", "@defaults[0]", "input", "DROP")], [])
sc_("defaults syn_flood", [("set", "firewall", "@defaults[0]", "synflood_protect", "0")], [])
sc_("include set", [("set", "firewall", "@include[0]", "enabled", "0")], ["exec-include"])
sc_("include path", [("set", "firewall", "@include[0]", "path", "/tmp/x.sh")], ["exec-include", "path-option"])
sc_("new include", [("newsec", "firewall", S("include", None, path="/tmp/x.sh"), "inc9")], ["exec-include", "path-option"])
sc_("firewall nat", [("newsec", "firewall", S("nat", None, name="n", src="wan"), "n1")], ["firewall-type"])
sc_("firewall ipset", [("newsec", "firewall", S("ipset", None, name="bad", match="src_ip"), "i1")], ["firewall-type"])
sc_("dhcpscript", [("set", "dhcp", "@dnsmasq[0]", "dhcpscript", "/bin/true")], ["exec-option", "path-option"])
sc_("leasetrigger", [("set", "dhcp", "@dnsmasq[0]", "leasetrigger", "/bin/true")], ["exec-option", "path-option"])
sc_("log_file", [("set", "system", "@system[0]", "log_file", "/tmp/x.log")], ["exec-option", "path-option"])
sc_("pppd_options", [("set", "network", "wan", "pppd_options", "debug")], ["exec-option"])
sc_("timezone slash", [("set", "system", "@system[0]", "timezone", "Europe/London")], ["path-option"])
sc_("ssid slash", [("set", "wireless", "@wifi-iface[0]", "ssid", "a/b")], ["path-option"])
sc_("prefix exempt", [("set", "dhcp", "@dnsmasq[0]", "foo", "10.0.0.0/8")], [])
sc_("v6 prefix exempt", [("set", "dhcp", "@dnsmasq[0]", "foo", "fd00::/48")], [])
sc_("https exempt", [("set", "dhcp", "@dnsmasq[0]", "foo", "https://dns.example/q")], [])
sc_("http exempt", [("set", "dhcp", "@dnsmasq[0]", "foo", "http://x")], [])
sc_("file url fires", [("set", "dhcp", "@dnsmasq[0]", "foo", "file:///etc/x")], ["path-option"])
sc_("rate exempt", [("set", "dhcp", "@dnsmasq[0]", "foo", "25/second")], [])
sc_("relative path fires", [("set", "dhcp", "@dnsmasq[0]", "foo", "foo/bar")], ["path-option"])
sc_("domain list fires", [("addlist", "dhcp", "@dnsmasq[0]", "address", "/x.lan/1.2.3.4")], ["path-option"])
sc_("deleted option with slash", [("delopt", "firewall", "@include[0]", "path")], ["exec-include", "path-option"])
sc_("ucitrack", [("set", "ucitrack", "@network[0]", "init", "x")], ["exec-config", "unknown-package"])
sc_("unknown package", [("newsec", "foo", S("thing", None, a="1"), "t1")], ["unknown-package"])
# newton_wanhealth is installed by newton-router-setup and is a known package
#. The change is a new settings section; no unknown-package code.
sc_("wanhealth main new", [("newsec", "newton_wanhealth", S("settings", "main", enabled="1", interval="5"), "main")], [])
sc_("upnp on", [("set", "upnpd", "config", "enabled", "1")], ["upnp-on"])
sc_("upnp off", [("set", "upnpd", "config", "enabled", "0")], [])
sc_("natpmp on", [("set", "upnpd", "config", "enable_natpmp", "1")], ["upnp-on"])
sc_("upnp on other", [("set", "upnpd", "config", "enable_upnp", "1")], ["upnp-on"])
sc_("ntp server open", [("set", "system", "ntp", "enable_server", "1")], ["ntp-server-open"])
sc_("ntp server with interface", [("set", "system", "ntp", "enable_server", "1"), ("set", "system", "ntp", "interface", "lan")], [])
sc_("ntp servers list", [("addlist", "system", "ntp", "server", "time.example")], [])
sc_("route on mgmt", [("newsec", "network", S("route", None, interface="lan", target="10.1.0.0/16", gateway="192.168.1.9"), "rt9")], ["mgmt-route"])
sc_("route on wan", [("newsec", "network", S("route", None, interface="wan", target="10.1.0.0/16", gateway="10.0.0.9"), "rt9")], [])
sc_("route6 on mgmt", [("newsec", "network", S("route6", None, interface="lan", target="fd00::/64", gateway="fd00::1"), "rt9")], ["mgmt-route"])
sc_("route existing set", [("set", "network", "r1", "gateway", "10.0.0.2")], [])
sc_("unparsed line", [("raw", "garbage")], ["unparsed-change"])
sc_("unparsed upper config", [("raw", "Firewall.x.y='1'")], ["unparsed-change"])
sc_("prod cosmetic", [("set", "system", "@system[0]", "hostname", "R2")], ["profile-prod"], profile="prod")
sc_("prod leash too", [("set", "dropbear", "@dropbear[0]", "Port", "2222")], ["profile-prod", "mgmt-config"], profile="prod")
sc_("rename option to dhcpscript", [("renameopt", "dhcp", "@dnsmasq[0]", "foo", "dhcpscript")], ["exec-option"])
sc_("rename option to log_file", [("renameopt", "system", "@system[0]", "timezone", "log_file")], ["exec-option"])
sc_("rename zone guest", [("renamesec", "firewall", "@zone[2]", "guestzone")], [])
sc_("rename zone guest then ACCEPT under the new name", [("renamesec", "firewall", "@zone[2]", "guestzone"), ("set", "firewall", "@zone[2]", "input", "ACCEPT", "new")], ["zone-exposure"])
sc_("rename lan zone then masq under the new name", [("renamesec", "firewall", "@zone[0]", "lanzone"), ("set", "firewall", "@zone[0]", "masq", "1", "new")], ["mgmt-zone"])
sc_("rename wan zone then device under the new name", [("renamesec", "firewall", "@zone[1]", "wanzone"), ("set", "firewall", "@zone[1]", "device", "x", "new")], ["wan-zone"])
sc_("custom zones: mgmt zone named mgmt", [("set", "firewall", "@zone[4]", "input", "ACCEPT")], ["mgmt-zone"], zones={"mgmt-interface": "lan", "mgmt-zone": "mgmt2", "wan-zone": ["wan"]})
sc_("custom zones: lan zone is ordinary", [("set", "firewall", "@zone[0]", "masq", "1")], ["mgmt-zone"], zones={"mgmt-interface": "lan", "mgmt-zone": "mgmt2", "wan-zone": ["wan"]})
sc_("two wan zones", [("set", "firewall", "@zone[2]", "input", "ACCEPT")], ["wan-zone"], zones={"mgmt-interface": "lan", "mgmt-zone": "lan", "wan-zone": ["wan", "guest"]})
sc_("custom mgmt interface", [("set", "network", "guest", "ipaddr", "192.168.7.1")], ["mgmt-interface"], zones={"mgmt-interface": "guest", "mgmt-zone": "lan", "wan-zone": ["wan"]})
sc_("lan interface not mgmt when custom", [("set", "network", "lan", "ipaddr", "192.168.9.1")], [], zones={"mgmt-interface": "guest", "mgmt-zone": "lan", "wan-zone": ["wan"]})



SCENARIO_IDS = [name for name, *_ in SCENARIOS]
