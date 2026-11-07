---
source: https://openwrt.org/docs/guide-user/base-system/dhcp
retrieved: 2026-10-03
license: CC BY-SA 4.0, (c) OpenWrt contributors (https://openwrt.org/license)
note: condensed markdown conversion of the wiki page (navigation dropped); verify exact values against the live page for anything critical. Items marked LEGACY are fw3/iptables/swconfig/opkg-era and differ on OpenWrt 25.12.
---

# /etc/config/dhcp (dnsmasq, odhcpd)

dnsmasq = DNS (53) + DHCPv4 (67). odhcpd = DHCPv6 (547) + RA + NDP. Apply: `service dnsmasq restart`, `service odhcpd restart`. Some options (ipset, dnssec) need the `dnsmasq-full` package.

## dnsmasq section (defaults)
```
config dnsmasq
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option rebind_protection '1'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	option expandhosts '1'
	option nonegcache '0'
	option cachesize '1000'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
	option nonwildcard '1'
	option localservice '1'
	option ednspacket_max '1232'
```
| Option | Default | Description |
|---|---|---|
| `domain` | lan | domain handed to clients |
| `local` | /lan/ | answer this domain locally |
| `domainneeded` | 1 | don't forward plain names |
| `boguspriv` | 1 | no upstream reverse lookups for private ranges |
| `expandhosts` | 1 | add domain to /etc/hosts names |
| `rebind_protection` | 1 | `--stop-dns-rebind` |
| `rebind_localhost` | 1 | allow 127/8 replies |
| `rebind_domain` | | list `'/example.com/'` allow RFC1918 answers |
| `cachesize` | 1000 | |
| `authoritative` | 1 | DHCP authoritative |
| `readethers` | 1 | read /etc/ethers |
| `leasefile` | /tmp/dhcp.leases | |
| `resolvfile` | /tmp/resolv.conf.d/resolv.conf.auto | |
| `noresolv` | 0 | ignore resolv file |
| `server` | | list of upstream DNS (`'1.1.1.1'`, `'/example.com/10.0.0.1'`) |
| `rev_server` | | reverse DNS servers per range |
| `address` | | list `'/example.com/1.2.3.4'` wildcard override |
| `interface`, `notinterface`, `listen_address` | all | listen restrictions |
| `nonwildcard` | 1 | bind-dynamic |
| `localservice` | 1 | answer only local subnets |
| `port` | 53 | `0` disables DNS |
| `logqueries` | 0 | |
| `logdhcp`, `quietdhcp` | 0 | |
| `dnssec`, `dnsseccheckunsigned` | 0 | dnsmasq-full |
| `ipset` | | `'/example.com/set4,set6'` dnsmasq-full |
| `filter_aaaa` / `filter_a` | 0 | strip AAAA / A |
| `strictorder`, `allservers` | 0 | upstream selection |
| `sequential_ip`, `noping` | 0 | DHCP allocation behaviour |
| `dhcpleasemax`, `dnsforwardmax` | 150 | |
| `min_cache_ttl`, `max_cache_ttl`, `max_ttl`, `local_ttl` | | TTL tuning |
| `addnhosts` | /tmp/hosts | extra hosts files |
| `confdir` | /tmp/dnsmasq<inst>.d | extra conf dir |
| `dhcpscript` | | lease hook script |
| `dhcp_boot`, `enable_tftp`, `tftp_root` | | PXE/TFTP |
| `add_local_fqdn`, `add_local_hostname`, `add_wan_fqdn` | | router's own DNS records |
| `rapidcommit`, `addmac`, `fqdn`, `cachelocal`, `localuse`, `nohosts`, `nonegcache`, `bogusnxdomain`, `queryport`, `minport`, `maxport`, `ednspacket_max` (1232), `logfacility`, `nodaemon`, `dhcphostsfile`, `serversfile`, `addnmount`, `dbus` | | see wiki |

## dhcp pool (one per served interface)
```
config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'
```
`interface` is the logical network name (lan), NOT the device (br-lan). `start` = offset from network address; `limit` = pool size.
| Option | Default | Description |
|---|---|---|
| `ignore` | 0 | 1 = don't serve this interface |
| `dhcpv4` | | `server` / `disabled` |
| `dhcpv6` | | `server` / `relay` / `disabled` |
| `ra` | | `server` / `relay` / `disabled` |
| `ndp` | | `relay` / `disabled` |
| `dhcp_option` | | list, e.g. `'3,192.168.1.1'`, `'6,192.168.1.1 8.8.8.8'`, `'26,1470'` |
| `dhcp_option_force` | | same, forced |
| `dynamicdhcp` | 1 | 0 = only static leases |
| `force` | 0 | serve even if another DHCP server seen |
| `dns` | | IPv6 DNS servers to announce (IPv4: use dhcp_option 6) |
| `dns_service` | 1 | announce own IPv6 as DNS |
| `ra_default` | 0 | 0 router w/ global IPv6, 1 even without, 2 neither |
| `ra_flags` | other-config | managed-config, other-config, home-agent, none |
| `ra_slaac` | 1 | set A flag |
| `ra_preference` | medium | high/medium/low |
| `ra_mininterval`/`ra_maxinterval`/`ra_lifetime` | 200/600/1800 | seconds |
| `ra_dns` | 1 | RFC8106 DNS in RA |
| `ra_mtu`, `ra_hoplimit`, `ra_reachabletime`, `ra_retranstime`, `ra_useleasetime`, `ra_offlink` | | RA tuning |
| `ra_management` | 1 | deprecated; use ra_flags |
| `max_preferred_lifetime`/`max_valid_lifetime` | 2700s/5400s | RFC 9096 |
| `ndproxy_routing`, `ndproxy_slave`, `master` | | relay modes |
| `networkid`, `instance`, `tag` | | dnsmasq tagging/instance binding |

## host (static lease)
```
config host
	option name 'nas'
	list mac '11:22:33:44:55:66'
	option ip '192.168.1.123'
	option leasetime 'infinite'
```
Options: `mac` (list), `duid`, `match_tag`, `instance`, `enable` (1), `ip` (or `ignore`), `hostid` (IPv6 suffix), `name`, `tag`, `dns` (0; add forward+reverse DNS entry), `broadcast`, `leasetime`. Need at least one of `mac`, `duid`, `name`. Alternative: `/etc/ethers` with `readethers`.

## boot (PXE)
`config boot`: `filename` (req), `serveraddress` (req), `servername` (req), `networkid`, `dhcp_option`, `force`, `instance`. odhcpd lacks root-path; use dnsmasq.

## Classifiers and tags
Section types `mac`, `tag`, `vendorclass`, `userclass`, `circuitid`, `remoteid`, `subscrid`: option named as the section type holds the match; `networkid` = tag assigned; `dhcp_option` list; `force`.

## ipset (dnsmasq-full)
```
config ipset
	list name 'ss_rules_dst_forward'
	list domain 'linkedin.com'
```

## DHCP relay
```
config relay 'id'
	option interface 'lan'
	option local_addr '1.1.1.1'
	option server_addr '2.2.2.2'
```
All four required.

## Local DNS records
`address` (wildcard incl. subdomains): `uci add_list dhcp.@dnsmasq[0].address='/example.com/192.168.1.5'`
Host record:
```
config hostrecord
	option name 'host2.example.com'
	option ip '192.168.1.2'
```
addn-hosts style:
```
config domain
	option name 'host3.example.com'
	option ip '192.168.1.3'
```
CNAME:
```
config hostrecord
    option name 'unifi.lan'
    option ip '192.168.17.65'
config cname
    option cname 'unifi'
    option target 'unifi.lan'
```
uci workflow:
```sh
uci add dhcp hostrecord
uci set dhcp.@hostrecord[-1].name=host2.example.com
uci set dhcp.@hostrecord[-1].ip=192.168.1.2
uci commit dhcp
service dnsmasq restart
```
Inspect leases: `cat /tmp/dhcp.leases`.
