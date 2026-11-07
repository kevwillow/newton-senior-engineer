---
source: https://openwrt.org/docs/guide-user/network/network_configuration
retrieved: 2026-10-03
license: CC BY-SA 4.0, (c) OpenWrt contributors (https://openwrt.org/license)
note: condensed markdown conversion of the wiki page (navigation dropped); verify exact values against the live page for anything critical. Items marked LEGACY are fw3/iptables/swconfig/opkg-era and differ on OpenWrt 25.12.
---

# /etc/config/network

Apply: `service network reload` (soft) or `service network restart` (hard). `ifdown wan6; ifup wan6` per interface. `wifi down; wifi up` for wireless. Inspect: `ubus list network.interface.*`, `ifstatus wan6`.

## globals
```
config globals 'globals'
	option ula_prefix 'fd27:70fa:5c1d::/48'
```
| Option | Type | Default | Description |
|---|---|---|---|
| `ula_prefix` | IPv6 prefix / `auto` | none | ULA prefix |
| `packet_steering` | 0/1/2 | 0 | 0 off, 1 on, 2 all CPUs |
| `dhcp_default_duid` | hex | DUID-UUID | default DUID |
| `tcp_l3mdev`/`udp_l3mdev` | bool | 0 | VRF accept toggles |
| `netifd_loglevel` | number | 2 | netifd log level |

## device
```
config device 'lan_br'
	option name 'br-lan'
	option type 'bridge'
	list ports 'lan1'
```
| Option | Description |
|---|---|
| `name` (required) | L3 device name; matches interface `device` |
| `type` | `bridge` (also `8021q`, `macvlan`, ...) |
| `ports` (list) | member L2 devices |
| `macaddr` | MAC override |
| `ifname` | base device for `macvlan`/`8021q` |
| `vid` | VLAN ID for type `8021q` |
| `mtu`, `rxpause`, `txpause`, `autoneg`, `speed`, `duplex` | link params |
| `table` | VRF routing table (default 10) |

## interface
```
config interface 'wan'
	option proto 'dhcp'
	option device 'eth1'
```
Protocols: `static`, `dhcp`, `dhcpv6`, `ppp`, `pppoe`, `pppoa`, `3g`, `qmi`, `ncm`, `wwan`, `hnet`, `pptp`, `6in4`, `aiccu`, `6to4`, `6rd`, `dslite`, `l2tp`, `relay`, `gre`/`gretap`, `grev6`/`grev6tap`, `vti`/`vtiv6`, `vxlan`, `none` (L2-only/unmanaged; used for VLAN trunks with no IP).

Common options: `device` (L3 device, e.g. `br-lan`, `br-lan.20`, `eth1`), `mtu`, `auto` (bring up at boot), `ipv6` (0/1), `force_link`, `disabled`, `ip4table`, `ip6table`, `ipaddr` (list, CIDR ok), `netmask`, `gateway`, `dns` (list), `peerdns`, `metric`, `ip6assign` (prefix length for LAN delegation), `sourcefilter` (wan6; set 0 for IPv6 NAT).

Bridge options (on the `device` section of type bridge): `bridge_empty`, `vlan_filtering` (0/1), `igmp_snooping`, `multicast_querier`, `query_interval` (12500), `query_response_interval` (1000), `last_member_interval` (100), `hash_max` (512), `robustness` (2), `stp`, `forward_delay` (2), `hello_time` (2), `priority` (32767), `ageing_time` (300), `max_age` (20).

## Example (DSA, current)
```
config interface 'loopback'
        option device 'lo'
        option proto 'static'
        list ipaddr '127.0.0.1/8'

config globals 'globals'
        option ula_prefix 'fd9f:acbd:1234::/48'
        option packet_steering '2'

config device
        option name 'br-lan'
        option type 'bridge'
        list ports 'lan1'
        list ports 'lan2'
        list ports 'lan3'
        list ports 'lan4'
        list ports 'lan5'

config interface 'lan'
        option device 'br-lan'
        option proto 'static'
        list ipaddr '192.168.1.1/24'
        option ip6assign '60'

config interface 'wan'
        option device 'eth1'
        option proto 'dhcp'

config interface 'wan6'
        option device 'eth1'
        option proto 'dhcpv6'
```

## LEGACY: swconfig example (pre-DSA devices; see dsa-vlans.md)
```
config device 'lan_br'
	option name 'br-lan'
	option type 'bridge'
	list ports 'eth0.1'
config interface 'wan'
	option device 'eth0.2'
	option proto 'dhcp'
config switch
	option name 'switch0'
	option reset '1'
	option enable_vlan '1'
config switch_vlan
	option device 'switch0'
	option vlan '1'
	option ports '1 2 3 4 5t'
config switch_vlan
	option device 'switch0'
	option vlan '2'
	option ports '0 5t'
```
LEGACY sections: `switch` (name, reset, enable_vlan, enable_mirror_rx/tx, mirror_monitor_port, mirror_source_port, arl_age_time, igmp_snooping, igmp_v3), `switch_vlan` (device, vlan, vid, ports with `t` = tagged), `switch_port` (device, port, pvid, enable_eee, igmp_snooping). Not applicable on DSA devices.
