"""The measured answers the owner flow needs that ``noinstall_answers.py`` does not hold.

The firewall config of a lab run (lab-r1, OpenWrt 25.12.5,
2026-10-30), copied byte for byte from the lab capture (the ``uci.get
{"config": "firewall"}`` answer and the ``uci.get {"config":
"firewall", "type": "zone"}`` answer).  ``noinstall_answers.py``
holds every other answer; the firewall one is here because the owner flow needs the
real zone, forwarding and rule shapes to build its backups from.

Nothing here is invented: a test that compares against this compares
against what the router answered.
"""

from __future__ import annotations

import json
from typing import Any


#: The measured firewall config of lab-r1.
ANSWERS: dict[str, str] = {
    "uci.get.firewall": r"""[0, {"values": {"cfg01e63d": {".anonymous": true, ".index": 0, ".name": "cfg01e63d", ".type": "defaults", "forward": "REJECT", "input": "REJECT", "output": "ACCEPT", "syn_flood": "1"}, "cfg02dc81": {".anonymous": true, ".index": 1, ".name": "cfg02dc81", ".type": "zone", "forward": "ACCEPT", "input": "ACCEPT", "name": "lan", "network": ["lan"], "output": "ACCEPT"}, "cfg03dc81": {".anonymous": true, ".index": 2, ".name": "cfg03dc81", ".type": "zone", "forward": "DROP", "input": "REJECT", "masq": "1", "mtu_fix": "1", "name": "wan", "network": ["wan", "wan6", "wan2"], "output": "ACCEPT"}, "cfg04ad58": {".anonymous": true, ".index": 3, ".name": "cfg04ad58", ".type": "forwarding", "dest": "wan", "src": "lan"}, "cfg0592bd": {".anonymous": true, ".index": 4, ".name": "cfg0592bd", ".type": "rule", "dest_port": "68", "family": "ipv4", "name": "Allow-DHCP-Renew", "proto": "udp", "src": "wan", "target": "ACCEPT"}, "cfg0692bd": {".anonymous": true, ".index": 5, ".name": "cfg0692bd", ".type": "rule", "family": "ipv4", "icmp_type": "echo-request", "name": "Allow-Ping", "proto": "icmp", "src": "wan", "target": "ACCEPT"}, "cfg0792bd": {".anonymous": true, ".index": 6, ".name": "cfg0792bd", ".type": "rule", "family": "ipv4", "name": "Allow-IGMP", "proto": "igmp", "src": "wan", "target": "ACCEPT"}, "cfg0892bd": {".anonymous": true, ".index": 7, ".name": "cfg0892bd", ".type": "rule", "dest_port": "546", "family": "ipv6", "name": "Allow-DHCPv6", "proto": "udp", "src": "wan", "target": "ACCEPT"}, "cfg0992bd": {".anonymous": true, ".index": 8, ".name": "cfg0992bd", ".type": "rule", "family": "ipv6", "icmp_type": ["130/0", "131/0", "132/0", "143/0"], "name": "Allow-MLD", "proto": "icmp", "src": "wan", "src_ip": "fe80::/10", "target": "ACCEPT"}, "cfg0a92bd": {".anonymous": true, ".index": 9, ".name": "cfg0a92bd", ".type": "rule", "family": "ipv6", "icmp_type": ["echo-request", "echo-reply", "destination-unreachable", "packet-too-big", "time-exceeded", "bad-header", "unknown-header-type", "router-solicitation", "neighbour-solicitation", "router-advertisement", "neighbour-advertisement"], "limit": "1000/sec", "name": "Allow-ICMPv6-Input", "proto": "icmp", "src": "wan", "target": "ACCEPT"}, "cfg0b92bd": {".anonymous": true, ".index": 10, ".name": "cfg0b92bd", ".type": "rule", "dest": "*", "family": "ipv6", "icmp_type": ["echo-request", "echo-reply", "destination-unreachable", "packet-too-big", "time-exceeded", "bad-header", "unknown-header-type"], "limit": "1000/sec", "name": "Allow-ICMPv6-Forward", "proto": "icmp", "src": "wan", "target": "ACCEPT"}, "cfg0c92bd": {".anonymous": true, ".index": 11, ".name": "cfg0c92bd", ".type": "rule", "dest": "lan", "name": "Allow-IPSec-ESP", "proto": "esp", "src": "wan", "target": "ACCEPT"}, "cfg0d92bd": {".anonymous": true, ".index": 12, ".name": "cfg0d92bd", ".type": "rule", "dest": "lan", "dest_port": "500", "name": "Allow-ISAKMP", "proto": "udp", "src": "wan", "target": "ACCEPT"}, "lab_wan": {".anonymous": false, ".index": 14, ".name": "lab_wan", ".type": "forwarding", "dest": "wan", "src": "lab"}, "labz": {".anonymous": false, ".index": 13, ".name": "labz", ".type": "zone", "forward": "ACCEPT", "input": "ACCEPT", "name": "lab", "network": ["lab"], "output": "ACCEPT"}}}]""",
    "uci.get.firewall.zone": r"""[0, {"values": {"cfg02dc81": {".anonymous": true, ".index": 1, ".name": "cfg02dc81", ".type": "zone", "forward": "ACCEPT", "input": "ACCEPT", "name": "lan", "network": ["lan"], "output": "ACCEPT"}, "cfg03dc81": {".anonymous": true, ".index": 2, ".name": "cfg03dc81", ".type": "zone", "forward": "DROP", "input": "REJECT", "masq": "1", "mtu_fix": "1", "name": "wan", "network": ["wan", "wan6", "wan2"], "output": "ACCEPT"}, "labz": {".anonymous": false, ".index": 13, ".name": "labz", ".type": "zone", "forward": "ACCEPT", "input": "ACCEPT", "name": "lab", "network": ["lab"], "output": "ACCEPT"}}}]""",
}


def answer(key: str) -> Any:
    """The measured answer, parsed."""
    return json.loads(ANSWERS[key])


def data(key: str) -> Any:
    """The data part of a measured answer."""
    parsed = answer(key)
    if not isinstance(parsed, list) or not parsed or parsed[0] != 0:
        raise ValueError(f"the measured answer {key!r} is not a success")
    return parsed[1] if len(parsed) > 1 else {}
