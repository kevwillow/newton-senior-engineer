import shlex

import pytest

import newton_mcp.server as server


@pytest.mark.parametrize("command", [
    "ip addr",
    "ip address show",
    "ip -4 addr",
    "ip -6 route",
    "ip route",
    "ip -4 route list table main",
    "ip route show table all",
    "ip link show dev br-lan",
    "ip -s link show dev eth0",
    "ip -d link show dev br-lan",
    "ip neigh show",
    "ip rule list",
    "ip rule show table 100",
    "ip route get 1.1.1.1",
    "ip -4 addr show dev br-lan",
])
def test_ip_read_grammar_accepts_read_only_commands(command):
    assert server.validate_read(command) == shlex.split(command)


@pytest.mark.parametrize("command", [
    "ip",
    "ip a",
    "ip r",
    "ip l",
    "ip n",
    "ip ro",
    "ip r d default",
    "ip ro fl all",
    "ip l s eth0 mtu 1280",
    "ip n f all",
    "ip a a 10.0.0.9/24 dev br-lan",
    "ip link set eth0 down",
    "ip route add default via 1.2.3.4",
    "ip route del default",
    "ip addr flush dev eth0",
    "ip -batch x",
    "ip -b x",
    "ip -force addr",
    "ip -n ns1 addr",
    "ip -netns x addr",
    "ip -o addr",
    "ip -j addr",
    "ip -4 -6 addr",
    "ip -s -s link",
    "ip addr show dev",
    "ip addr show dev eth0 dev eth1",
    "ip route show table",
    "ip link show table main",
    "ip addr show extra",
    "ip monitor",
    "ip xfrm state",
    "ip tunnel show",
    "ip route get -1.1.1.1",
    "ip addr show dev -eth0",
])
def test_ip_read_grammar_rejects_other_commands(command):
    with pytest.raises(server.NewtonError, match=r"read command is not allowed: ip"):
        server.validate_read(command)
