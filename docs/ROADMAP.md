# Roadmap

Newton ships one 1.x release per platform group. In every release, "supported" means the same seven scenarios pass
(a normal change, a management lockout that undoes itself, a firewall lockout that undoes itself, an injection attempt
rejected, bad syntax rejected, a service still reachable after the change, and an uplink failure that undoes itself),
and the support table ([`SUPPORT.md`](SUPPORT.md)) names the undo method and what is not tested.

## Released

| Release | Ships |
|---|---|
| 1.0 | OpenWrt 25.12 (a virtual router and a real Asus RT-AX57M), with experimental VyOS, MikroTik RouterOS and Junos changes tested on virtual images; the one-line setup, in-client approvals, undo after confirm, client-side checks and change receipts |
| 1.1 | The no-install mode for OpenWrt: Newton puts nothing on the router but one limited web-interface user, talks to the router's own web API over pinned HTTPS, applies only DHCP reservations and DNS entries by itself under OpenWrt's own undo timer, and hands every other change to the owner as a script; the installed mode stays one command away |

## Planned

| Release | Ships |
|---|---|
| 1.2 | Network promises (owner-written rules such as "the work laptop reaches the printer" or "IoT cannot reach the router admin", re-checked from a client on every change that touches them); reviewed recipes for common jobs (guest or IoT network, DHCP reservations, WireGuard, port forward, DNS, bufferbloat); the blast radius before approval (the Wi-Fi networks, VLANs and devices that depend on what a change touches); a recovery card before a risky change; a generated network map and read-only report pages written as local files |
| 1.3 | Linux hosts: network configuration, the local firewall and a hardening level, tested per network stack |
| 1.4 | OpenWrt firmware upgrades: exact image, signed checksum, off-device backup, settings kept, the router program reinstalled, verified over a fresh connection. An upgrade has no undo, so it is always high risk |
| 1.5 | Site files and rollouts: a confirmed change saved as a readable site file and applied to other devices one plan and one approval each; then a canary-first rollout across many devices that stops at the first failure; maintenance windows |
| 1.x | More vendors (Arista EOS, FortiOS, Cisco IOS XE), each when its seven scenarios pass |

Plans change; [`CHANGELOG.md`](../CHANGELOG.md) is the record of what shipped.
