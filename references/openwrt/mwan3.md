---
source: https://openwrt.org/docs/guide-user/network/wan/multiwan/mwan3
retrieved: 2026-10-03
license: CC BY-SA 4.0, (c) OpenWrt contributors (https://openwrt.org/license)
note: condensed markdown conversion of the wiki page (navigation dropped); verify exact values against the live page for anything critical. Items marked LEGACY are fw3/iptables/swconfig/opkg-era and differ on OpenWrt 25.12.
---

> **Checked against the live wiki (raw page, 2026-10-03):** "It is no longer recommended to use the
> official mwan3 package at this time, given it is based on iptables, which is no longer the firewall
> backend of OpenWrt." The OpenWrt 25.12.5 aarch64 feed (verified on Quasar with `apk search`) offers
> `mwan3-2.12.0-r3` (iptables-based) and `pbr-1.2.2-r20` (policy-based routing); no nftables mwan3.
> The wiki points to a separate unofficial nftables page (`.../multiwan/mwan3-nft`). Full raw page:
> `source/mwan3.txt`.

# mwan3 (multi-WAN)

LEGACY WARNING: mwan3 is iptables/ipset based. The wiki states it is no longer recommended on 25.12 (iptables approach), unlikely to work properly on 24.10, needs `iptables-nft`/`ip6tables-nft` on 22.03+, and ipset (dnsmasq) integration is broken from 23.05 (workaround: nft2ipset init script). For 25.12 prefer plain policy routing: multiple `wan` interfaces with different `metric`, or `ip rule`/nft marks, and check whether a nftables-native mwan3 build exists before relying on this page.
Install (opkg-era commands on the page): `opkg update; opkg install mwan3 luci-app-mwan3` -> on 25.12 use `apk add mwan3 luci-app-mwan3`.

Concepts: interfaces (health tracking) -> members (interface + metric + weight) -> policies (group of members) -> rules (match traffic -> policy). Firewall mask `mmx_mask` default `0x3F00`. Need at least 2 members to be useful. Load balancing is per-connection, not bonding.

## globals
`mmx_mask` (0x3F00), `logging` (0), `loglevel` (notice), `rtmon_interval` (5, deprecated since 2.9.0), `rt_table_lookup`.

## interface
| Option | Default | Description |
|---|---|---|
| (section name) | | must match `/etc/config/network` interface |
| `enabled` | 0 | |
| `family` | ipv4 | ipv4/ipv6 |
| `track_method` | ping | ping arping httping nping-tcp nping-udp nping-icmp nping-arp |
| `track_ip` | | list of hosts to probe |
| `reliability` | 1 | how many track_ip must reply |
| `count` | 1 | probes per test |
| `timeout` | 4 | seconds |
| `interval` | 10 | seconds between tests |
| `failure_interval`, `recovery_interval` | interval | |
| `keep_failure_interval` | 0 | |
| `up`/`down` | 5/5 | successes/failures before state change |
| `check_quality`, `failure_latency` (1000), `recovery_latency` (500), `failure_loss` (40), `recovery_loss` (10) | | quality checks |
| `initial_state` | online | |
| `flush_conntrack` | | list, e.g. `ifup` |
| `max_ttl` (60), `size` (56) | | probe params |
Reliable probe IPs: Google 8.8.8.8/8.8.4.4, Cloudflare 1.1.1.1/1.0.0.1, Quad9 9.9.9.9/149.112.112.112, OpenDNS 208.67.222.222/208.67.220.220 (IPv6 equivalents on page).
```
config interface 'wan'
	option enabled '1'
	list track_ip '1.0.0.1'
	list track_ip '1.1.1.1'
	option family 'ipv4'
	option reliability '2'
```

## member
```
config member 'wan_m1_w3'
	option interface 'wan'
	option metric '1'
	option weight '3'
```
Lower metric = higher precedence; equal metrics share load by weight.

## policy
Name max 15 chars `[A-Za-z0-9_]`.
```
config policy 'balanced'
	list use_member 'wan_m1_w3'
	list use_member 'wanb_m1_w3'
	option last_resort 'unreachable'
```
`last_resort`: `unreachable` (ICMP reject, default) | `blackhole` (drop) | `default` (main table).
Failover pattern: member A metric 1, member B metric 2 in the same policy (`wan_wanb`).

## rule
Name max 15 chars. Matched top-down; first match wins; unmatched traffic uses main routing table.
| Option | Default | |
|---|---|---|
| `use_policy` | required | policy or `default` |
| `src_ip`, `src_port`, `dest_ip`, `dest_port` | any | comma-separated lists allowed |
| `proto` | all | tcp udp icmp all |
| `ipset` | | |
| `sticky` | 0 | reuse same WAN for same flow |
| `timeout` | 600 | stickiness seconds |
| `family` | any | |
| `logging` | 0 | |
```
config rule 'https'
	option sticky '1'
	option dest_port '443'
	option proto 'tcp'
	option use_policy 'balanced'
config rule 'default_rule_v4'
	option dest_ip '0.0.0.0/0'
	option family 'ipv4'
	option use_policy 'wan_wanb'
```
Pin one LAN host to one WAN:
```
config rule 'mailserver_uses_wanb_only'
	option src_ip '172.16.1.20'
	option family 'ipv4'
	option use_policy 'wanb_only'
```

## Single physical WAN port: macvlan
```
config device 'veth5'
    option name 'veth5'
    option type 'macvlan'
    option ifname 'eth1'
```
(needs `kmod-macvlan`).

## CLI
```sh
mwan3 status | interfaces | policies | rules | connected
mwan3 start | stop | restart
mwan3 ifup <iface> | ifdown <iface>
mwan3 use <iface> <cmd>      # run a command bound to a WAN, e.g. mwan3 use wanb ping -4 example.com
ip route show table <n>
```
Hotplug hook script: `/etc/mwan3.user` with `$ACTION` (ifup/ifdown/connected/disconnected), `$INTERFACE`, `$DEVICE` (empty on ifdown).

## Interop notes
- WireGuard behind mwan3: flush conntrack for the WG port on `connected`/`disconnected` events in `/etc/mwan3.user` (`conntrack -D -p udp --dport <port>`).
- OpenVPN client as virtual WAN: `route-nopull` + `route 0.0.0.0 0.0.0.0 vpn_gateway 20`.
- Multiple external IPs: extra static interfaces in the wan zone + `redirect` with `target SNAT` and `src_dip` (see port-forwards.md).
- iperf3 / ddns / NoDogSplash notes: see live wiki.
