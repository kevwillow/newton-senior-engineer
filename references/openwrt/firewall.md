---
source: https://openwrt.org/docs/guide-user/firewall/firewall_configuration
retrieved: 2026-10-03
license: CC BY-SA 4.0, (c) OpenWrt contributors (https://openwrt.org/license)
note: condensed markdown conversion of the wiki page (navigation dropped); verify exact values against the live page for anything critical. Items marked LEGACY are fw3/iptables/swconfig/opkg-era and differ on OpenWrt 25.12.
---

# /etc/config/firewall (fw4 / nftables)

OpenWrt 22.03+ uses firewall4 (nftables backend). Apply with `service firewall reload` (or restart). Inspect generated ruleset: `fw4 print`, `nft list ruleset`. LuCI strips comments from the file.
Minimal config: one `defaults`, at least two `zone` (lan, wan), one `forwarding` (lan -> wan).
```sh
uci add firewall rule
uci set firewall.@rule[-1].name='Reject VPN to LAN traffic'
uci set firewall.@rule[-1].src='vpn'
uci set firewall.@rule[-1].dest='lan'
uci set firewall.@rule[-1].proto='all'
uci set firewall.@rule[-1].target='REJECT'
uci commit firewall
service firewall restart
```

## defaults
```
config defaults
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option drop_invalid '1'
	option synflood_protect '1'
	option synflood_rate '25/s'
	option synflood_burst '50'
	option tcp_ecn '1'
	option tcp_syncookies '1'
	option tcp_window_scaling '1'
```
| Option | Default | Description |
|---|---|---|
| `input`/`output`/`forward` | ACCEPT/ACCEPT/REJECT | chain policies |
| `drop_invalid` | 0 | drop invalid conntrack packets |
| `synflood_protect` | 0 | SYN flood protection (`syn_flood` = LEGACY name) |
| `synflood_rate`/`synflood_burst` | 25/s, 50 | limits |
| `tcp_syncookies` | 1 | |
| `tcp_ecn` | 0 | 0 off, 1 on, 2 ingress only |
| `tcp_window_scaling` | 1 | |
| `accept_redirects`, `accept_source_route` | 0 | |
| `custom_chains` | 1 | hook chains for user rules |
| `flow_offloading` | 0 | software flow offload |
| `flow_offloading_hw` | 0 | hardware offload (needs flow_offloading=1) |
| `tcp_reject_code`, `any_reject_code` | 0, 1 | reject method |
| `auto_helper` | 1 | conntrack helpers |
| `auto_includes` | 1 | fw4: auto-include `/usr/share/nftables.d/` |
| `disable_ipv6` | 0 | LEGACY, not supported by fw4 |

## zone
```
config zone
	option name 'wan'
	option network 'wan wan6'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'
```
INPUT = traffic to the router from the zone; OUTPUT = from router out via the zone; FORWARD = between interfaces inside the same zone. Masquerade is per outgoing zone.
| Option | Default | Description |
|---|---|---|
| `name` | required | max 11 chars |
| `network` | zone name | list of interface names |
| `device` | | L3 devices (e.g. `tun+`) for undeclared interfaces |
| `subnet` | | subnets in zone |
| `masq` | 0 lan / 1 wan | IPv4 masquerade |
| `masq6` | 0 | IPv6 masquerade (fw4; needs `sourcefilter 0` on wan6) |
| `masq_src`, `masq_dest` | 0.0.0.0/0 | limit masquerade by subnet, `!` negates |
| `masq_allow_invalid` | 0 | skip DROP INVALID for masq |
| `mtu_fix` | 0 lan / 1 wan | MSS clamping |
| `input`/`output`/`forward` | from defaults | ACCEPT REJECT DROP |
| `family` | auto | ipv4 ipv6 any |
| `log`, `log_limit` | 0, 10/minute | |
| `extra`, `extra_src`, `extra_dest` | | LEGACY iptables args |
| `custom_chains`, `enabled`, `auto_helper`, `helper` | | |

## forwarding
One direction per section; add a reverse section for bidirectional.
```
config forwarding
	option src 'lan'
	option dest 'wan'
```
Options: `name`, `src` (required), `dest` (required), `family` (any), `enabled`. Needs conntrack; at least one zone masquerading for NAT.

## rule
```
config rule
	option name 'Reject LAN to WAN for custom IP'
	option src 'lan'
	option src_ip '192.168.1.2'
	option src_mac '00:11:22:33:44:55'
	option src_port '80'
	option dest 'wan'
	option dest_ip '194.25.2.129'
	option dest_port '120'
	option proto 'tcp'
	option target 'REJECT'
```
Inter-zone forward within a REJECT-forward zone:
```
config rule
	option name 'forward ssh to server'
	option family 'ipv4'
	option src 'lan'
	option src_ip '192.168.1.0/24'
	option dest 'lan'
	option dest_ip '172.30.100.1'
	option proto 'tcp'
	option dest_port '22'
	option target 'ACCEPT'
```
Classification: `src`+`dest` = forward rule; only `src` = input (to router); only `dest` = output; neither = output. CIDR allowed. Ports: `6666-6670`, multiple space-separated.
| Option | Default | Description |
|---|---|---|
| `name`, `enabled`, `family` | | |
| `src`, `src_ip`, `src_mac`, `src_port` | | source match |
| `dest`, `dest_ip`, `dest_port` | | destination match |
| `proto` | tcp udp | tcp udp udplite icmp esp ah sctp all or number |
| `icmp_type` | any | list of names/numbers |
| `ipset` | | set name, `!` negates, optional `src`/`dest` direction |
| `mark` | | fwmark match `0xFF`, `!` inverts |
| `start_date` `stop_date` `start_time` `stop_time` `weekdays` `monthdays` `utc_time` | | time-based matching |
| `target` | DROP | ACCEPT REJECT DROP MARK NOTRACK |
| `set_mark`, `set_xmark` | | for MARK target |
| `limit`, `limit_burst` | , 5 | e.g. `3/minute` |
| `device`, `direction`, `helper`, `set_helper` | | marked FIXME on wiki |
| `extra` | | LEGACY iptables args |

ICMP type names: address-mask-reply, address-mask-request, any, communication-prohibited, destination-unreachable, echo-reply, echo-request, fragmentation-needed, host-precedence-violation, host-prohibited, host-redirect, host-unknown, ip-header-bad, network-prohibited, network-redirect, network-unknown, parameter-problem, ping, pong, port-unreachable, precedence-cutoff, protocol-unreachable, redirect, required-option-missing, router-advertisement, router-solicitation, source-quench, source-route-failed, time-exceeded, timestamp-reply, timestamp-request, TOS-*, ttl-exceeded, ttl-zero-during-reassembly, ttl-zero-during-transit.

## redirect (DNAT/SNAT)
See port-forwards.md for the full option table and examples.

## ipset (named sets)
fw4 options: `enabled`, `comment`, `name` (required), `family` (ipv4), `match` (list e.g. `src_port`, `dest_net`), `maxelem` (65536), `timeout` (0), `entry` (list), `loadfile`, `counters`. Types: prefix `src_`/`dest_`, suffix `ip` `port` `mac` `net` (`set` unsupported in fw4). LEGACY (fw3) extras: `external`, `storage` (bitmap/hash/list), `iprange`, `portrange`, `netmask`, `hashsize`. See ../nftables/sets.md.

## include
fw4 nftables snippets:
```
config include
	option type 'nftables'
	option path '/etc/my_custom_firewall_rule.nft'
	option position 'chain-pre'
	option chain 'input_wan'
```
File content example: `tcp dport 0-1023 log prefix "Inbound WAN connection attempt to low TCP port: "`
Options: `enabled`, `type` (`script` default | `nftables`), `path`, `position` (default `table-post`), `chain` (for chain-*).
Positions: `ruleset-pre`, `ruleset-post`, `table-pre`, `table-post`, `chain-pre`, `chain-post` (aliases `-prepend`, `-postpend`/`-append`).
Script include under fw4:
```
config include
	option type 'script'
	option path '/etc/firewall.user'
	option fw4_compatible '1'
```
fw4 has no `family`/`reload` include options. `/etc/nftables.d/*.nft` is auto-included at table-pre. Package drop-ins: `/usr/share/nftables.d/{ruleset-pre,ruleset-post,table-pre,table-post}/*.nft` and `chain-pre/<chain>/*.nft`, `chain-post/<chain>/*.nft` (readable, `.nft` extension).
LEGACY fw3 includes: `type` script|restore (iptables-restore), `family`, `reload`; `/etc/firewall.user` was the default script.

## Notes
- Prefer UCI config over raw nft where possible; back up `/etc/config/firewall` before edits.
- Debug structure: `fw4 print`.
