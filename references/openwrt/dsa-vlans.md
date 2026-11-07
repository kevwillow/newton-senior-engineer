---
source: https://openwrt.org/docs/guide-user/network/dsa/start ; .../dsa/dsa-mini-tutorial ; .../dsa/converting-to-dsa ; .../network/vlan/switch_configuration
retrieved: 2026-10-03
license: CC BY-SA 4.0, (c) OpenWrt contributors (https://openwrt.org/license)
note: condensed markdown conversion of the wiki page(s) (navigation dropped); verify exact values against the live page for anything critical. Items marked LEGACY are fw3/iptables/swconfig/opkg-era and differ on OpenWrt 25.12.
---

# DSA and VLANs

DSA (Distributed Switch Architecture) replaced swconfig from 21.02 on most targets. Each switch port is its own netdev (`lan1`, `lan2`, `wan` ...). DSA config is incompatible with swconfig. DSA does not affect `/etc/config/wireless`.
Detect DSA:
```sh
grep -sq DEVTYPE=dsa /sys/class/net/*/uevent && echo DSA
```
Targets on DSA by release: 21.02 ath79 (WR941ND only), bcm4908, gemini, kirkwood, mediatek, mvebu, octeon, ramips mt7621, realtek; 22.03 bcm53xx, lantiq xrx200, sunxi Lamobo R1; 23.05 ipq40xx; 24.10 ipq806x, airoha; 25.12 at91, gemini, ixp4xx. Not all devices are migrated: check before choosing swconfig vs DSA syntax.

## Key differences from swconfig
- No `eth0.2` CPU-port tagging. Make a VLAN subinterface of the bridge: `br-lan.2`. Set that as the interface `device`.
- Router joins a VLAN automatically via `br-lan.<vid>`; `option local '0'` on a `bridge-vlan` stops creating that L3 device (use for VLANs the router should not be on).
- Wireless interfaces join the right VLAN just by `option network '<iface>'`; no tagged-ethernet bridging needed.
- Bridge VLAN filtering is implied by `bridge-vlan` sections.

## Port flags in `bridge-vlan` `list ports`
- `lan1` (no flag) = untagged egress member.
- `lan1:t` = tagged (egress tagged; untagged ingress dropped unless PVID is elsewhere).
- `lan1:u*` = untagged + PVID (untagged ingress is assigned to this VLAN). A port can be PVID in only one VLAN.
- Port not listed = not a member of that VLAN.
Ingress = frame entering bridge via port; egress = leaving.

## 1. One bridge, all ports
```
config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'lan1'
	list ports 'lan2'
	list ports 'lan3'
	list ports 'lan4'
config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
```

## 2. Separate bridges per group
```
config device
	option name 'br-home'
	option type 'bridge'
	list ports 'lan1'
	list ports 'lan2'
config device
	option name 'office'
	option type 'bridge'
	list ports 'lan3'
	list ports 'lan4'
config interface 'home'
	option device 'br-home'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
config interface 'office'
	option device 'office'
	option proto 'static'
	option ipaddr '192.168.13.1'
	option netmask '255.255.255.0'
```
Isolated unless firewall allows forwarding.

## 3. VLANs on one bridge (access ports)
```
config device
	option name 'br-lan'
	option type 'bridge'
	list ports 'lan1'
	list ports 'lan2'
	list ports 'lan3'
	list ports 'lan4'
config bridge-vlan
	option device 'br-lan'
	option vlan '1'
	list ports 'lan1'
	list ports 'lan2'
config bridge-vlan
	option device 'br-lan'
	option vlan '2'
	list ports 'lan3'
	list ports 'lan4'
config interface 'home'
	option device 'br-lan.1'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
config interface 'office'
	option device 'br-lan.2'
	option proto 'static'
	option ipaddr '192.168.13.1'
	option netmask '255.255.255.0'
```

## 4. Trunk port (tagged + untagged)
```
config bridge-vlan
	option device 'br-lan'
	option vlan '1'
	list ports 'lan1'
	list ports 'lan2'
	list ports 'lan3'
	list ports 'lan4:t'
config bridge-vlan
	option device 'br-lan'
	option vlan '2'
	list ports 'lan4:u*'
```

## 5. VLANs without IP on the router, firewall zones
Every managed interface needs a firewall zone. `proto 'none'` interfaces stay L2-only.
```
config device 'switch'
	option name 'switch'
	option type 'bridge'
	list ports 'lan1'
	list ports 'lan2'
	list ports 'lan3'
	list ports 'lan4'
config bridge-vlan 'lan_vlan'
	option device 'switch'
	option vlan '1'
	list ports 'lan1:u*'
	list ports 'lan4:t'
config bridge-vlan
	option device 'switch'
	option vlan '2'
	list ports 'lan1:u*'
	list ports 'lan4:t'
config bridge-vlan
	option device 'switch'
	option vlan '3'
	list ports 'lan3:u*'
	list ports 'lan4:t'
config interface 'lan'
	option proto 'dhcp'
	option device 'switch.1'
config interface 'iot'
	option proto 'none'
	option device 'switch.2'
config interface 'guest'
	option proto 'none'
	option device 'switch.3'
```
(Note: the wiki example lists `lan1:u*` in two VLANs; a port has one PVID, so treat as a doc quirk and verify with `bridge vlan show`.)

## 6. Hardening: avoid VLAN 1, parking VLAN, trunk native VLAN
- Do not use VLAN 1 for data networks.
- Give trunk ports an unused native VLAN, tagged-only for real VLANs.
- Park unused ports in an unused VLAN with `option local '0'`.
Matrix example (VLAN 10 on lan1/lan2 tagged, lan3 untagged; 20 and 30 tagged on lan1/lan2; VLAN 90 parking):
```
config bridge-vlan 'lan_vlan'
	option device 'switch'
	option vlan '10'
	list ports 'lan1:t'
	list ports 'lan2:t'
	list ports 'lan3:u*'
config bridge-vlan
	option device 'switch'
	option vlan '20'
	list ports 'lan1:t'
	list ports 'lan2:t'
config bridge-vlan
	option device 'switch'
	option vlan '30'
	list ports 'lan1:t'
	list ports 'lan2:t'
config bridge-vlan
	option device 'switch'
	option vlan '90'
	list ports 'lan1:u*'
	list ports 'lan2:u*'
	list ports 'lan4:u*'
	option local '0'
config interface 'lan'
	option proto 'dhcp'
	option device 'switch.10'
config interface 'iot'
	option proto 'none'
	option device 'switch.20'
```

## Converting swconfig -> DSA
swconfig:
```
config switch_vlan
	option device 'switch0'
	option vlan '1'
	option ports '0 1 2 3 5t'
config switch_vlan
	option device 'switch0'
	option vlan '2'
	option ports '4 6t'
```
DSA equivalent:
```
config device
	option type 'bridge'
	option name 'br0'
	list ports 'lan1'
	list ports 'lan2'
	list ports 'lan3'
	list ports 'lan4'
	list ports 'wan'
config bridge-vlan
	option device 'br0'
	option vlan '1'
	list ports 'lan1:u*'
	list ports 'lan2:u*'
	list ports 'lan3:u*'
	list ports 'lan4:u*'
config bridge-vlan
	option device 'br0'
	option vlan '2'
	list ports 'wan:u*'
config interface 'lan'
	option device 'br0.1'
	option proto 'dhcp'
```
Steps: put all switch ports (incl. wan) into one bridge; one `bridge-vlan` per VLAN; interface device = `<bridge>.<vid>`.

## LEGACY: swconfig switch VLANs (non-DSA devices only)
```
config switch
	option reset '1'
	option enable_vlan '1'
config switch_vlan
	option device 'switch0'
	option vlan '1'
	option ports '0 1 3t 5t'
config switch_port
	option device 'switch0'
	option port '3'
	option pvid '3'
```
`t` = tagged. CPU port is tagged; WAN/LAN default split is VLAN1 LAN, VLAN2 WAN.
LEGACY driver VLANs: `config device` with `option type '8021q'`, `option ifname 'eth0'`, `option vid '106'`, `option name 'vlan1'`, or implicit `eth0.106`.

## Verify
```sh
bridge vlan show
bridge link
ip -d link show br-lan
```
