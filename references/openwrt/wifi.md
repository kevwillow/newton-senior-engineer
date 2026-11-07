---
source: https://openwrt.org/docs/guide-user/network/wifi/basic
retrieved: 2026-10-03
license: CC BY-SA 4.0, (c) OpenWrt contributors (https://openwrt.org/license)
note: condensed markdown conversion of the wiki page (navigation dropped); verify exact values against the live page for anything critical. Items marked LEGACY are fw3/iptables/swconfig/opkg-era and differ on OpenWrt 25.12.
---

# /etc/config/wireless (wpad / hostapd / wpa_supplicant)

Wireless is OFF by default on devices with Ethernet ports (`option disabled '1'` on radios). Apply: `wifi reload` (or `wifi down; wifi up`, `wifi up wlan2`). Regenerate defaults: `rm -f /etc/config/wireless; wifi config`. Regulatory check: `iw reg get`.
Encryption modes WPA3/SAE/OWE/802.11r/k/v need the full `wpad` package (not `wpad-basic*`) as appropriate.

## wifi-device (radio)
```
config wifi-device 'radio0'
	option type 'mac80211'
	option path 'pci0000:00/0000:00:00.0'
	option band '5g'
	option channel '36'
	option htmode 'VHT80'
	option country 'DE'
```
| Option | Description |
|---|---|
| `type` | `mac80211` (modern) / `broadcom` (LEGACY) |
| `phy`, `path` | radio identity (autodetected) |
| `disabled` | 1 = off |
| `channel` | number or `auto` |
| `band` | `2g`, `5g`, `6g`, `60g` (replaces `hwmode`) |
| `hwmode` | LEGACY `11b/11g/11a`, deprecated since 21.02.2 |
| `htmode` | `HT20`, `HT40-`, `HT40+`, `VHT20/40/80/160`, `HE20/40/80/160`, `NOHT` |
| `txpower` | dBm |
| `country` | 2-letter code |
| `beacon_int` | default 100 |
| `legacy_rates` | allow 802.11b (0 in 21.02+) |
| `require_mode` | `n` or `ac` minimum client |
| `chanbw` (5/10/20), `noscan`, `ht_coex`, `frag`, `rts`, `antenna_gain` | mac80211 extras |

HT40+/- = position of the secondary channel. DFS channels (e.g. 52-144) need DFS support in the image; if `DFS start_dfs_cac() failed, -1` appears with HT40, use HT20. Check: `iw phy1 info`, `logread -f`.

## wifi-iface (an SSID)
```
config wifi-iface 'default_radio0'
	option device 'radio0'
	option network 'lan'
	option mode 'ap'
	option ssid 'MyWifiAP'
	option encryption 'psk2'
	option key 'secret passphrase'
```
| Option | Default | Description |
|---|---|---|
| `device` | | radio section name |
| `network` | lan | logical interface(s) to attach (list) |
| `mode` | ap | `ap`, `sta`, `adhoc`, `monitor`, `mesh` |
| `ssid` | OpenWrt | |
| `bssid` | | override |
| `mesh_id` | | 802.11s mesh id |
| `hidden` | 0 | |
| `isolate` | 0 | client isolation (AP) |
| `bridge_isolate` | 0 | |
| `wmm` | 1 | |
| `encryption` | none | see table |
| `key` | | PSK / WEP key |
| `macfilter` | disable | `allow`, `deny` |
| `maclist` | | MAC list |
| `maxassoc` | | |
| `dtim_period` | 2 | |
| `wds` | 0 | 4-address mode |
| `disabled` | 0 | |
| `macaddr` | | override, supports `random` |
| `ieee80211w` | 0 | MFP: 0 off, 1 optional, 2 required |
| `sae_require_mfp` | 1 | |
| `ieee80211k` / `rrm_neighbor_report` / `rrm_beacon_report` | 0 | 802.11k |
| `bss_transition`, `wnm_sleep_mode`, `time_advertisement`, `time_zone` | 0 | 802.11v |
| `ieee80211r`, `mobility_domain`, `nasid`, `ft_over_ds`, `ft_psk_generate_local`, `r0kh`, `r1kh`, `pmk_r1_push`, `r0_key_lifetime`, `r1_key_holder`, `reassociation_deadline` | | 802.11r fast roaming |
| `owe_transition_ssid`, `owe_transition_bssid` | | OWE transition |
| `mlo` | 0 | multi-link operation |
| `max_inactivity` (300), `disassoc_low_ack` (1), `skip_inactivity_poll`, `max_listen_interval` | | inactivity |
| `wpa_disable_eapol_key_retries`, `tdls_prohibit`, `rsn_preauth`, `doth`, `start_disabled` | | misc AP |
| `wpa_psk_file` | | per-MAC/VLAN passphrase file |
| `hostapd_bss_options`, `hostapd_options` | | raw hostapd passthrough |
| `wps_pushbutton`, `wps_config`, `wps_device_name`, `wps_pin` ... | | WPS |

### encryption values
| Value | Meaning |
|---|---|
| `none` | open |
| `owe` | Opportunistic Wireless Encryption |
| `sae` | WPA3 Personal |
| `sae-mixed` | WPA2/WPA3 Personal |
| `psk2` / `psk2+ccmp` | WPA2 Personal (CCMP) |
| `psk2+tkip+ccmp` | WPA2 Personal (TKIP+CCMP) |
| `psk-mixed` | WPA/WPA2 Personal |
| `psk+tkip+ccmp` | WPA Personal (LEGACY) |
| `wep`, `wep+shared` | WEP (LEGACY, insecure) |
| `wpa3`, `wpa3-mixed`, `wpa2`, `wpa` | Enterprise (RADIUS) |

WPA Enterprise AP options: `server`, `port` (1812), `key` (RADIUS secret), `auth_server`, `auth_port`, `auth_secret`, `dynamic_vlan` (0/1/2), `vlan_naming`, `vlan_tagged_interface`, `wpa_group_rekey` (600). Client: `eap_type` (tls/peap/ttls), `auth` (MSCHAPV2), `identity`, `password`, `ca_cert`, `client_cert`, `priv_key`, `priv_key_pwd`.

## wifi-station / wifi-vlan (per-PSK VLANs; SAE supported since 24.10)
```
config wifi-station
	option iface 'iface_radio0'
	option vid '10'
	option mac '12:34:56:78:90:00'
	option key 'hunter12'
config wifi-vlan
	option iface 'iface_radio0'
	option network 'dmz'
	option vid '10'
	option name '10'
```
wifi-station: `iface`, `vid`, `mac`, `key` (required). wifi-vlan: `iface`, `vid` (req), `network` (req), `name` (req, max 14 minus interface name length).

## Examples
Basic WPA2 AP (see wifi-device/iface above). DFS 5 GHz Germany: radio `channel '104'`, `htmode 'HT20'`, `country 'DE'`.
Client (STA) uplink pattern: `option mode 'sta'`, `option network 'wwan'`, `option ssid '...'`, `option encryption 'psk2'`, `option key '...'` (the `wwan` interface then needs its own `proto dhcp` network section and a wan firewall zone; not spelled out on the page).

## HT/VHT capability flags (rarely needed)
HT: `ldpc`, `greenfield`, `short_gi_20/40`, `tx_stbc`, `rx_stbc`, `max_amsdu`, `dsss_cck_40`. VHT: `rxldpc`, `short_gi_80/160`, `su_beamformer/ee`, `mu_beamformer/ee`, `vht_txop_ps`, `htc_vht`, `vht_max_a_mpdu_len_exp`, `vht_max_mpdu`, `vht_link_adapt`, `vht160`, `rx_antenna_pattern`, `tx_antenna_pattern`.
