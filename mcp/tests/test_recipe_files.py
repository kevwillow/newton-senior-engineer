"""The seven recipe files of the repo: the exact batches they resolve to.

The recipes are read from the repo's own ``profiles/openwrt/recipes``
(no fixture): these are the files Newton ships, so what they resolve to
is pinned here, line by line.  A recipe that drifts changes what the
router is told to do, so the whole batch and the whole probe list are
written out.

The rules these tests hold:

* all seven files load, and a file that does not load is listed with its
  error, never skipped silently;
* one golden test per recipe: the exact ``uci_batch`` and the exact
  probes, from a full set of synthetic values;
* an optional param drops the step and the check that need it, and a
  step whose param nobody gave is refused by the name of that param;
* every golden batch is accepted by the touched check the plan path
  runs on the resolved lines (ADR-010), and its probes pass the
  router's own probe grammar;
* every delete in a recipe follows a set of the same path in the same
  step: a delete of a missing entry fails the whole uci batch on a
  stock router (measured on lab-r1);
* the dns-upstream recipe leaves a LIST dnsmasq's init reads, and its
  checks read dnsmasq's own generated conf;
* on a router Newton cannot install on, Newton applies the DHCP
  reservation and the DNS entry itself and turns every other change
  into an owner script.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from newton_mcp import noinstall_checks
from newton_mcp import probes
from newton_mcp import recipes as recipes_mod
from newton_mcp import touched
from newton_mcp.recipes import RecipeError


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "profiles" / "openwrt" / "manifest.toml"

#: The seven recipe ids, in the order the listing sorts them.
RECIPE_IDS = (
    "bufferbloat",
    "dhcp-reservation",
    "dns-host",
    "dns-upstream",
    "guest-network",
    "port-forward",
    "wireguard",
)


@pytest.fixture(autouse=True)
def the_real_recipes_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    """The recipes dir of this repo, whatever the environment says.

    ``recipes.recipes_dir()`` sits next to the manifest, so the manifest
    of the repo is pointed at: the tests below read the files that ship.
    """
    monkeypatch.setenv("NEWTON_MANIFEST", str(MANIFEST))


# ---- the values ------------------------------------------------------------


#: A synthetic MAC address (the documentation shape).
MAC = "02:00:00:00:00:01"
#: A 44-character test key: the base64 of 32 bytes, so it is a WireGuard
#: public key and a Wi-Fi passphrase at once.  Synthetic, never a real key.
TEST_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
#: The Wi-Fi name of the tests.
SSID = "newton-test"

#: The values of each recipe: a full set, every param given.
VALUES: dict[str, dict[str, str]] = {
    "guest-network": {
        "purpose": "guest",
        "addr": "192.168.50.1/24",
        "radio": "radio0",
        "net_ssid": SSID,
        "net_key": TEST_KEY,
        "isolate": "1",
    },
    "dhcp-reservation": {
        "name": "laptop",
        "host": "laptop",
        "mac": MAC,
        "ip": "192.168.50.10",
    },
    "port-forward": {
        "name": "web",
        "proto": "tcp",
        "outside_port": "8080",
        "inside_ip": "192.168.50.30",
        "inside_port": "80",
    },
    "dns-host": {
        "name": "nas",
        "host": "nas",
        "ip": "192.168.50.20",
    },
    "dns-upstream": {
        "server1": "192.0.2.53",
        "server2": "198.51.100.53",
    },
    "wireguard": {
        "addr": "10.99.0.1/24",
        "port": "51820",
        "peer": "wg_peer",
        "peer_key": TEST_KEY,
        "peer_ip": "10.99.0.2",
    },
    "bufferbloat": {
        "device": "eth1",
        "down": "100000",
        "up": "10000",
    },
}


# ---- the golden batches ----------------------------------------------------


GUEST_BATCH = """\
set network.guest_dev=device
set network.guest_dev.type='bridge'
set network.guest_dev.name='br-guest'
set network.guest_dev.bridge_empty='1'
set network.guest=interface
set network.guest.proto='static'
set network.guest.device='br-guest'
set network.guest.ipaddr='192.168.50.1/24'
set dhcp.guest=dhcp
set dhcp.guest.interface='guest'
set dhcp.guest.start='100'
set dhcp.guest.limit='150'
set dhcp.guest.leasetime='12h'
set firewall.guest_zone=zone
set firewall.guest_zone.name='guest'
add_list firewall.guest_zone.network='guest'
set firewall.guest_zone.input='REJECT'
set firewall.guest_zone.output='ACCEPT'
set firewall.guest_zone.forward='REJECT'
set firewall.guest_fwd=forwarding
set firewall.guest_fwd.src='guest'
set firewall.guest_fwd.dest='wan'
set firewall.guest_dhcp=rule
set firewall.guest_dhcp.name='Allow-guest-DHCP'
set firewall.guest_dhcp.src='guest'
set firewall.guest_dhcp.proto='udp'
set firewall.guest_dhcp.dest_port='67'
set firewall.guest_dhcp.target='ACCEPT'
set firewall.guest_dns=rule
set firewall.guest_dns.name='Allow-guest-DNS'
set firewall.guest_dns.src='guest'
set firewall.guest_dns.proto='tcp udp'
set firewall.guest_dns.dest_port='53'
set firewall.guest_dns.target='ACCEPT'
set wireless.guest_wifi=wifi-iface
set wireless.guest_wifi.device='radio0'
set wireless.guest_wifi.mode='ap'
set wireless.guest_wifi.network='guest'
set wireless.guest_wifi.ssid='newton-test'
set wireless.guest_wifi.encryption='sae-mixed'
set wireless.guest_wifi.key='AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
set wireless.guest_wifi.isolate='1'
"""

GUEST_PROBES = [
    ["uci-equals", "network.guest.proto", "static"],
    ["uci-equals", "firewall.guest_zone.input", "REJECT"],
    ["uci-equals", "firewall.guest_zone.forward", "REJECT"],
    ["uci-equals", "wireless.guest_wifi.network", "guest"],
]

#: The golden batch of the guest network with a wired port: the golden
#: batch plus the one line that names the port, right after the first
#: step's lines.
GUEST_PORT_BATCH = """\
set network.guest_dev=device
set network.guest_dev.type='bridge'
set network.guest_dev.name='br-guest'
set network.guest_dev.bridge_empty='1'
set network.guest=interface
set network.guest.proto='static'
set network.guest.device='br-guest'
set network.guest.ipaddr='192.168.50.1/24'
set dhcp.guest=dhcp
set dhcp.guest.interface='guest'
set dhcp.guest.start='100'
set dhcp.guest.limit='150'
set dhcp.guest.leasetime='12h'
set firewall.guest_zone=zone
set firewall.guest_zone.name='guest'
add_list firewall.guest_zone.network='guest'
set firewall.guest_zone.input='REJECT'
set firewall.guest_zone.output='ACCEPT'
set firewall.guest_zone.forward='REJECT'
set firewall.guest_fwd=forwarding
set firewall.guest_fwd.src='guest'
set firewall.guest_fwd.dest='wan'
set firewall.guest_dhcp=rule
set firewall.guest_dhcp.name='Allow-guest-DHCP'
set firewall.guest_dhcp.src='guest'
set firewall.guest_dhcp.proto='udp'
set firewall.guest_dhcp.dest_port='67'
set firewall.guest_dhcp.target='ACCEPT'
set firewall.guest_dns=rule
set firewall.guest_dns.name='Allow-guest-DNS'
set firewall.guest_dns.src='guest'
set firewall.guest_dns.proto='tcp udp'
set firewall.guest_dns.dest_port='53'
set firewall.guest_dns.target='ACCEPT'
add_list network.guest_dev.ports='eth3.30'
set wireless.guest_wifi=wifi-iface
set wireless.guest_wifi.device='radio0'
set wireless.guest_wifi.mode='ap'
set wireless.guest_wifi.network='guest'
set wireless.guest_wifi.ssid='newton-test'
set wireless.guest_wifi.encryption='sae-mixed'
set wireless.guest_wifi.key='AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
set wireless.guest_wifi.isolate='1'
"""

RESERVATION_BATCH = """\
set dhcp.laptop=host
set dhcp.laptop.name='laptop'
set dhcp.laptop.mac='02:00:00:00:00:01'
set dhcp.laptop.ip='192.168.50.10'
"""

RESERVATION_PROBES = [
    ["uci-equals", "dhcp.laptop.mac", "02:00:00:00:00:01"],
    ["uci-equals", "dhcp.laptop.ip", "192.168.50.10"],
]

FORWARD_BATCH = """\
set firewall.web=redirect
set firewall.web.name='web'
set firewall.web.src='wan'
set firewall.web.src_dport='8080'
set firewall.web.dest='lan'
set firewall.web.dest_ip='192.168.50.30'
set firewall.web.dest_port='80'
set firewall.web.proto='tcp'
set firewall.web.target='DNAT'
"""

FORWARD_PROBES = [
    ["uci-equals", "firewall.web.dest_ip", "192.168.50.30"],
    ["uci-equals", "firewall.web.src_dport", "8080"],
]

DNS_HOST_BATCH = """\
set dhcp.nas=domain
set dhcp.nas.name='nas'
set dhcp.nas.ip='192.168.50.20'
"""

DNS_HOST_PROBES = [
    ["uci-equals", "dhcp.nas.ip", "192.168.50.20"],
]

DNS_UPSTREAM_BATCH = """\
set dhcp.@dnsmasq[0].server='192.0.2.53'
delete dhcp.@dnsmasq[0].server
add_list dhcp.@dnsmasq[0].server='192.0.2.53'
set dhcp.@dnsmasq[0].noresolv='1'
add_list dhcp.@dnsmasq[0].server='198.51.100.53'
"""

#: The golden batch of the dns-upstream recipe with one resolver only: the
#: second one is optional, and the step that names it is dropped.
DNS_UPSTREAM_ONE_BATCH = """\
set dhcp.@dnsmasq[0].server='192.0.2.53'
delete dhcp.@dnsmasq[0].server
add_list dhcp.@dnsmasq[0].server='192.0.2.53'
set dhcp.@dnsmasq[0].noresolv='1'
"""

DNS_UPSTREAM_PROBES = [
    ["uci-equals", "dhcp.@dnsmasq[0].noresolv", "1"],
    ["conf-has", "dnsmasq", "line", "present", "server=192.0.2.53"],
    ["conf-has", "dnsmasq", "line", "present", "server=198.51.100.53"],
]

#: The golden probes of the dns-upstream recipe with one resolver only:
#: the second one is optional, so the check that names it is dropped.
DNS_UPSTREAM_ONE_PROBES = [
    ["uci-equals", "dhcp.@dnsmasq[0].noresolv", "1"],
    ["conf-has", "dnsmasq", "line", "present", "server=192.0.2.53"],
]

WIREGUARD_BATCH = """\
set network.wg0=interface
set network.wg0.proto='wireguard'
set network.wg0.listen_port='51820'
set network.wg0.addresses='10.99.0.1/24'
set network.wg_peer=wireguard_wg0
set network.wg_peer.public_key='AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
set network.wg_peer.allowed_ips='10.99.0.2/32'
set firewall.wg_zone=zone
set firewall.wg_zone.name='wg'
set firewall.wg_zone.network='wg0'
set firewall.wg_zone.input='ACCEPT'
set firewall.wg_zone.output='ACCEPT'
set firewall.wg_zone.forward='REJECT'
set firewall.wg_lan=forwarding
set firewall.wg_lan.src='wg'
set firewall.wg_lan.dest='lan'
set firewall.wg_in=rule
set firewall.wg_in.name='Allow-WireGuard'
set firewall.wg_in.src='wan'
set firewall.wg_in.proto='udp'
set firewall.wg_in.dest_port='51820'
set firewall.wg_in.target='ACCEPT'
"""

WIREGUARD_PROBES = [
    ["uci-equals", "network.wg0.proto", "wireguard"],
    ["uci-equals", "firewall.wg_in.dest_port", "51820"],
    ["uci-equals", "network.wg_peer.allowed_ips", "10.99.0.2/32"],
]

BUFFERBLOAT_BATCH = """\
set sqm.newton_wan=queue
set sqm.newton_wan.enabled='1'
set sqm.newton_wan.interface='eth1'
set sqm.newton_wan.download='100000'
set sqm.newton_wan.upload='10000'
set sqm.newton_wan.qdisc='cake'
set sqm.newton_wan.script='piece_of_cake.qos'
set sqm.newton_wan.linklayer='none'
"""

BUFFERBLOAT_PROBES = [
    ["uci-equals", "sqm.newton_wan.enabled", "1"],
    ["uci-equals", "sqm.newton_wan.interface", "eth1"],
]

#: The golden batch and the golden probes of each recipe.
GOLDEN: dict[str, tuple[str, list[list[str]]]] = {
    "guest-network": (GUEST_BATCH, GUEST_PROBES),
    "dhcp-reservation": (RESERVATION_BATCH, RESERVATION_PROBES),
    "port-forward": (FORWARD_BATCH, FORWARD_PROBES),
    "dns-host": (DNS_HOST_BATCH, DNS_HOST_PROBES),
    "dns-upstream": (DNS_UPSTREAM_BATCH, DNS_UPSTREAM_PROBES),
    "wireguard": (WIREGUARD_BATCH, WIREGUARD_PROBES),
    "bufferbloat": (BUFFERBLOAT_BATCH, BUFFERBLOAT_PROBES),
}


def _resolve(recipe_id: str) -> dict:
    """The recipe of the repo, resolved with its golden values."""
    recipe = recipes_mod.load_recipe(recipe_id)
    return recipes_mod.resolve(recipe, VALUES[recipe_id])


# ---- the listing -----------------------------------------------------------


def test_the_seven_recipes_load() -> None:
    """Every recipe of the repo loads, and none of them is broken.

    A file that does not load is listed with its error, never skipped:
    the owner sees that a recipe file is broken.
    """
    listed = recipes_mod.list_recipes("openwrt")

    broken = [entry for entry in listed if "error" in entry]
    assert not broken, broken
    assert [entry["id"] for entry in listed] == list(RECIPE_IDS)


# ---- the golden batches ----------------------------------------------------


@pytest.mark.parametrize("recipe_id", RECIPE_IDS)
def test_the_golden_batch_of_a_recipe(recipe_id: str) -> None:
    """A recipe resolves to the exact batch and the exact probes.

    The whole text is pinned: a recipe that drifts changes what the
    router is told to do.
    """
    batch, expected_probes = GOLDEN[recipe_id]

    resolved = _resolve(recipe_id)

    assert resolved["uci_batch"] == batch
    assert resolved["probes"] == expected_probes


# ---- the optional params ----------------------------------------------------


def test_the_guest_network_without_a_wifi_name_has_no_wireless_line() -> None:
    """Without a Wi-Fi name the guest network is wired only: the step and
    the check that need it are dropped."""
    recipe = recipes_mod.load_recipe("guest-network")

    resolved = recipes_mod.resolve(
        recipe, {"purpose": "guest", "addr": "192.168.50.1/24"}
    )

    assert "wireless." not in resolved["uci_batch"]
    assert len(resolved["probes"]) == 3
    assert resolved["probes"] == [
        ["uci-equals", "network.guest.proto", "static"],
        ["uci-equals", "firewall.guest_zone.input", "REJECT"],
        ["uci-equals", "firewall.guest_zone.forward", "REJECT"],
    ]


def test_the_guest_network_with_a_port_adds_the_ports_line() -> None:
    """A guest network with a wired port: the batch has one line more than
    the golden one, the ports line, right after the first step's lines.

    The port is optional: without it the batch is the golden one.
    """
    recipe = recipes_mod.load_recipe("guest-network")

    resolved = recipes_mod.resolve(
        recipe, dict(VALUES["guest-network"], port="eth3.30")
    )

    assert resolved["uci_batch"] == GUEST_PORT_BATCH
    assert resolved["probes"] == GUEST_PROBES
    # exactly one line more than the golden batch, and it is the ports line
    extra = [line for line in GUEST_PORT_BATCH.splitlines()
             if line not in GUEST_BATCH.splitlines()]
    assert extra == ["add_list network.guest_dev.ports='eth3.30'"]
    # the ports line sits right after the first step's lines, before the
    # Wi-Fi step's lines
    lines = GUEST_PORT_BATCH.splitlines()
    assert lines[lines.index("add_list network.guest_dev.ports='eth3.30'") - 1] \
        == "set firewall.guest_dns.target='ACCEPT'"
    assert lines[lines.index("add_list network.guest_dev.ports='eth3.30'") + 1] \
        == "set wireless.guest_wifi=wifi-iface"


def test_the_guest_network_without_a_port_has_no_ports_line() -> None:
    """Without a port the guest network has no ports line: the step that
    needs it is dropped."""
    recipe = recipes_mod.load_recipe("guest-network")

    resolved = recipes_mod.resolve(recipe, VALUES["guest-network"])

    assert "ports=" not in resolved["uci_batch"]
    assert resolved["uci_batch"] == GUEST_BATCH


def test_the_guest_network_with_a_wifi_name_but_no_passphrase_is_refused() -> None:
    """A Wi-Fi name needs the radio and the passphrase, and the refusal
    names the param nobody gave, never the value."""
    recipe = recipes_mod.load_recipe("guest-network")

    with pytest.raises(RecipeError) as exc:
        recipes_mod.resolve(
            recipe,
            {
                "purpose": "guest",
                "addr": "192.168.50.1/24",
                "radio": "radio0",
                "net_ssid": SSID,
            },
        )

    message = str(exc.value)
    assert "net_key" in message, message


def test_the_dns_upstream_without_a_second_server_names_one_server() -> None:
    """The second resolver is optional: without it the batch names one
    server, and it is a LIST dnsmasq's init reads (a set, a delete and
    an add_list), not a plain option."""
    recipe = recipes_mod.load_recipe("dns-upstream")

    resolved = recipes_mod.resolve(recipe, {"server1": "192.0.2.53"})

    assert resolved["uci_batch"] == DNS_UPSTREAM_ONE_BATCH
    assert resolved["probes"] == DNS_UPSTREAM_ONE_PROBES


def test_the_dns_upstream_batch_leaves_a_list_dnsmasq_reads() -> None:
    """The last write to the dnsmasq server option is an add_list.

    OpenWrt's dnsmasq init reads ``server`` with ``config_list_foreach``,
    which skips a plain option, so a batch whose last write is a ``set``
    is a change dnsmasq ignores: the router came up with ``no-resolv``
    and no upstream at all (measured on lab-r1, 2026-11-27).  The batch
    writes the list with an ``add_list``, and the recipe's own check
    reads dnsmasq's generated conf, so a batch dnsmasq ignores can no
    longer confirm.
    """
    resolved = _resolve("dns-upstream")

    lines = resolved["uci_batch"].splitlines()
    noresolv = next(
        index for index, line in enumerate(lines)
        if line.startswith("set dhcp.@dnsmasq[0].noresolv=")
    )
    writes = [
        line for line in lines[:noresolv]
        if "dhcp.@dnsmasq[0].server" in line
    ]

    assert writes, writes
    assert writes[-1].startswith("add_list "), writes[-1]


# ---- the uci lines a recipe may use -----------------------------------------


#: The uci verbs that take something away.
DELETE_VERBS = ("delete", "del_list")


def _uci_path(text: str) -> str:
    """The UCI path of one batch line: its second word, without its value."""
    words = text.split(None, 1)
    if len(words) < 2:
        return ""
    return words[1].split("=", 1)[0].strip()


def _deletes_without_a_set(lines: list[str]) -> list[str]:
    """The delete lines of one step that no earlier set of the same path covers.

    A delete of a missing entry fails the whole uci batch on a stock
    router (measured on lab-r1): ``uci batch`` rejects every line of the
    batch when one of them deletes an entry that is not there, and the
    router answers ``uci: Entry not found``.  So a recipe may only
    delete a path an EARLIER line of the SAME step has set: the set
    makes sure the entry is there, and the delete drops what it wrote.
    """
    set_paths: set[str] = set()
    offenders: list[str] = []
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        words = text.split(None, 1)
        verb = words[0]
        rest = words[1] if len(words) > 1 else ""
        if verb == "set" and "=" in rest:
            set_paths.add(_uci_path(text))
        elif verb in DELETE_VERBS and _uci_path(text) not in set_paths:
            offenders.append(text)
    return offenders


def test_every_delete_in_a_shipped_recipe_follows_a_set_of_its_path() -> None:
    """Every delete in a shipped recipe follows a set of the same path.

    A delete of a missing entry fails the whole uci batch on a stock
    router (measured on lab-r1): ``uci batch`` rejects every line of the
    batch when one of them deletes an entry that is not there, and the
    router answers ``uci: Entry not found``.  A stock dnsmasq section has
    no ``server`` option, so the dns-upstream recipe's delete stopped
    every change on a router that had never been configured.

    A recipe may therefore delete a path, but only one an earlier line
    of the SAME step has set: the set makes sure the entry is there.
    """
    recipes_dir = recipes_mod.recipes_dir()

    offenders: list[str] = []
    for path in sorted(recipes_dir.glob("*.toml")):
        recipe = recipes_mod.load_recipe(path.stem)
        for step in recipe["steps"]:
            for offender in _deletes_without_a_set(step["text"].splitlines()):
                offenders.append(f"{path.stem}: {offender}")

    assert not offenders, offenders


def test_the_delete_helper_refuses_a_bare_delete() -> None:
    """The helper bites: a delete of a path nobody set is an offender.

    Without this case the rule above could hold while checking nothing.
    """
    allowed = [
        "set dhcp.@dnsmasq[0].server='10.100.0.1'",
        "delete dhcp.@dnsmasq[0].server",
    ]
    assert _deletes_without_a_set(allowed) == []

    refused = ["delete dhcp.@dnsmasq[0].server"]
    assert _deletes_without_a_set(refused) == refused


# ---- the plan path's touched check ------------------------------------------


@pytest.mark.parametrize("recipe_id", RECIPE_IDS)
def test_every_golden_batch_passes_the_touched_check(recipe_id: str) -> None:
    """The plan path derives the touched controls from the RESOLVED lines
    and seals their probes together with the recipe's own probes
    (ADR-010): the derivation accepts every golden batch, the seal does
    not refuse it, and the recipe's probes pass the router's own probe
    grammar."""
    resolved = _resolve(recipe_id)

    entries = touched.derive_touched_entries(resolved["uci_batch"])
    assert isinstance(entries, list)

    sealed, manifest_probes = touched.seal_manifest_ids(
        [], entries, extra_probes=resolved["probes"]
    )
    assert sealed == entries

    # the recipe's own probes are sealed with the manifest's, in the same
    # cap: a plan that does not fit is refused, never trimmed
    assert probes.validate_probes(resolved["probes"]) == resolved["probes"]
    assert len(manifest_probes) + len(resolved["probes"]) <= probes.MAX_PROBE_LINES
    assert (
        touched.sealed_probes_bytes(manifest_probes)
        + touched.sealed_probes_bytes(resolved["probes"])
        <= probes.MAX_PROBES_BYTES
    )


# ---- the no-install decision ------------------------------------------------


def test_the_no_install_decision_of_a_dhcp_reservation_is_auto() -> None:
    """A DHCP reservation is one of the two changes Newton applies itself
    on a router it cannot install on."""
    batch = _resolve("dhcp-reservation")["uci_batch"]

    auto, reason = noinstall_checks.auto_apply_decision(batch, risk="low")

    assert auto is True, reason


def test_the_no_install_decision_of_a_dns_host_is_auto() -> None:
    """A local name that answers with an address is the other one."""
    batch = _resolve("dns-host")["uci_batch"]

    auto, reason = noinstall_checks.auto_apply_decision(batch, risk="low")

    assert auto is True, reason


def test_the_no_install_decision_of_a_wireguard_is_not_auto() -> None:
    """A tunnel and its firewall zone are not on the list Newton applies
    itself: the change becomes an owner script."""
    batch = _resolve("wireguard")["uci_batch"]

    auto, reason = noinstall_checks.auto_apply_decision(batch, risk="low")

    assert auto is False, reason
