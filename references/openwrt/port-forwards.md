---
source: https://openwrt.org/docs/guide-user/firewall/firewall_configuration (redirect section) ; .../fw3_configurations/fw3_nat
retrieved: 2026-10-03
license: CC BY-SA 4.0, (c) OpenWrt contributors (https://openwrt.org/license)
note: condensed markdown conversion of the wiki page (navigation dropped); verify exact values against the live page for anything critical. Items marked LEGACY are fw3/iptables/swconfig/opkg-era and differ on OpenWrt 25.12.
---

# Port forwards, redirects, NAT (fw4)

Port forwards are `config redirect` sections. Apply: `service firewall reload`.

## DNAT port forward
```
config redirect
	option name 'Example of SSH DNAT'
	option target 'DNAT'
	option src 'wan'
	option dest 'lan'
	option proto 'tcp'
	option src_dport '2222'
	option dest_ip '192.0.2.20'
	option dest_port '22'
	option enabled '1'
```
Test from WAN side: `ssh -p 2222 203.0.113.8`. Omitting `src_dport` forwards ALL ports to the host: always set it.
Match a specific WAN IP (ICMP):
```
config redirect
	option src 'wan'
	option src_dip '1.2.3.4'
	option proto 'icmp'
	option dest 'lan'
	option dest_ip '192.0.2.20'
	option target 'DNAT'
	option name 'DNAT-ICMP-WAN-LAN'
```
Different internal port (mail 25 -> 2525):
```
config redirect
	option target 'DNAT'
	option src 'wan'
	option src_dport '25'
	option proto 'tcp'
	option family 'ipv4'
	option dest 'lan'
	option dest_ip '192.0.2.20'
	option dest_port '2525'
	option name 'DNAT-MAIL-SERVER'
```
Via uci:
```sh
uci add firewall redirect
uci set firewall.@redirect[-1].name='ssh-nas'
uci set firewall.@redirect[-1].target='DNAT'
uci set firewall.@redirect[-1].src='wan'
uci set firewall.@redirect[-1].dest='lan'
uci set firewall.@redirect[-1].proto='tcp'
uci set firewall.@redirect[-1].src_dport='2222'
uci set firewall.@redirect[-1].dest_ip='192.0.2.20'
uci set firewall.@redirect[-1].dest_port='22'
uci commit firewall && service firewall reload
```
(The uci form is an equivalent of the config block above, not on the wiki page.)

## Redirect options
| Option | Default | Description |
|---|---|---|
| `name` | | |
| `src` | required for DNAT | source zone (usually wan) |
| `src_ip`, `src_mac`, `src_port` | | source matches |
| `src_dip` | required for SNAT | DNAT: match dest IP; SNAT: rewrite source address |
| `src_dport` | | DNAT: match dest port; SNAT: rewrite source port |
| `dest` | required for SNAT | destination zone |
| `dest_ip`, `dest_port` | | DNAT: target host/port; SNAT: match dest |
| `proto` | tcp udp | |
| `target` | DNAT | DNAT or SNAT |
| `family` | ipv4 | ipv4 ipv6 any |
| `reflection` | 1 | NAT loopback (DNAT only) |
| `reflection_src` | internal | `internal` or `external` |
| `reflection_zone` | | zones with reflection |
| `mark`, time-match options, `limit`, `limit_burst` | | as in rules |
| `ipset` | | unsupported in fw4 for redirect |
| `enabled` | 1 | |
| `extra` | | LEGACY iptables args |

## SNAT
```
config redirect
	option target 'SNAT'
	option src 'lan'
	option dest 'wan'
	option proto 'tcp'
	option src_ip '192.0.2.20'
	option src_dip '192.0.2.13'
	option dest_port '8080'
```

## Masquerade (the common case)
Enable on the WAN zone: `option masq '1'`, or:
```sh
uci set firewall.@zone[1].masq="1"
uci commit firewall
service firewall restart
```
IPv6 NAT: `uci set firewall.@zone[1].masq6="1"`; also `uci set dhcp.lan.ra_default="1"` (then `service odhcpd restart`) and `uci set network.wan6.sourcefilter="0"` (then `service network restart`).

## Selective NAT (masquerade one source subnet)
```sh
uci -q delete firewall.nat
uci set firewall.nat="nat"
uci set firewall.nat.family="ipv4"
uci set firewall.nat.proto="all"
uci set firewall.nat.src="wan"
uci set firewall.nat.src_ip="192.168.2.0/24"
uci set firewall.nat.target="MASQUERADE"
uci commit firewall
service firewall restart
```
IPv6: same with `nat6`, `family ipv6`, `src_ip fd00:2::/64`.

## IPv6 NPT
```sh
cat << "EOF" > /etc/nftables.d/npt6.sh
LAN_PFX="$(uci -q get network.globals.ula_prefix)"
. /lib/functions/network.sh
network_flush_cache
network_find_wan6 WAN_IF
network_get_device WAN_DEV "${WAN_IF}"
network_get_prefix6 WAN_PFX "${WAN_IF}"
nft add rule inet fw4 srcnat \
oifname "${WAN_DEV}" snat ip6 prefix to ip6 \
saddr map { "${LAN_PFX}" : "${WAN_PFX}" }
EOF
uci -q delete firewall.npt6
uci set firewall.npt6="include"
uci set firewall.npt6.path="/etc/nftables.d/npt6.sh"
uci commit firewall
service firewall restart
```

## Transparent proxy
```
config redirect
	option src 'lan'
	option proto 'tcp'
	option src_ip '!192.168.1.100'
	option src_dport '80'
	option dest_ip '192.168.1.100'
	option dest_port '3128'
	option target 'DNAT'
config redirect
	option dest 'lan'
	option proto 'tcp'
	option src_dip '192.168.1.1'
	option dest_ip '192.168.1.100'
	option dest_port '3128'
	option target 'SNAT'
```

## Protocol helpers
FTP/SIP/RTSP passthrough needs conntrack helper kernel modules (`kmod-nf-nathelper`, `kmod-nf-nathelper-extra`, `kmod-ipt-nathelper-rtsp`). The wiki shows `opkg install`: LEGACY, on 25.12 use `apk add <pkg>` (see packages-apk.md).
