---
source: https://openwrt.org/docs/guide-user/base-system/uci
retrieved: 2026-10-03
license: CC BY-SA 4.0, (c) OpenWrt contributors (https://openwrt.org/license)
note: condensed markdown conversion of the wiki page (navigation dropped); verify exact values against the live page for anything critical. Items marked LEGACY are fw3/iptables/swconfig/opkg-era and differ on OpenWrt 25.12.
---

# UCI (Unified Configuration Interface)

Central config system; files live in `/etc/config/`.

## Concepts
- Config = a file (network, system, firewall ...). Section = a block, named or anonymous. Type = section type label. Option = key. Value = setting. `list` = multi-value option.

## File syntax
```
config 'type' 'name'
    option 'key' 'value'
    list 'items' 'entry1'
    list 'items' 'entry2'
```
- `#` comments. Quotes only needed for values with spaces/tabs.
- Identifiers: `a-z 0-9 _` only (no hyphens).
- Booleans: `0/no/false/off` and `1/yes/true/on`.

## Main files
| File | Purpose |
|---|---|
| `/etc/config/network` | interfaces, devices, bridge-vlan, routes |
| `/etc/config/wireless` | wifi |
| `/etc/config/firewall` | zones, rules, redirects, NAT (fw4/nftables) |
| `/etc/config/dhcp` | dnsmasq, odhcpd, static leases, DNS records |
| `/etc/config/system` | hostname, timezone, NTP, LEDs |
| `/etc/config/dropbear` | SSH server |

## CLI
```sh
uci show [config[.section[.option]]]   # dump (use this to find section names)
uci get config.section.option
uci set config.section.option='value'
uci add config type                    # anonymous section, prints its id
uci add_list config.section.option='v'
uci del_list config.section.option='v'
uci delete config.section[.option]
uci rename config.section=newname
uci changes [config]                   # staged diff, not yet on flash
uci revert config                      # drop staged changes
uci commit [config]                    # write to flash
```
- Anonymous section addressing: `config.@type[0]` first, `config.@type[-1]` last, `@type[-2]` second last.
- Example:
```sh
uci set network.lan.ipaddr='192.168.2.1'
uci commit network
/etc/init.d/network restart     # or: service network restart / reload
```

## Rules of thumb
- `uci set` only stages; nothing applies until `uci commit` AND the service is reloaded/restarted (`service firewall reload`, `service dnsmasq restart`, `service network reload`, `wifi reload`).
- init scripts regenerate daemon configs from UCI; hand-edits of generated files are overwritten.
- `uci` rewrites the file and drops comments (so does LuCI).
- Inspect before and after with `uci show <config>`; stage with `uci changes`.
