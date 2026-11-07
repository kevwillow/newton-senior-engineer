# Pulsar scenarios

Ports of the lab scenarios to Pulsar, the physical OpenWrt dev router. Pulsar is a development device that may be
reset and rebooted. It is never Quasar, which is production and is never a test device. Every scenario here has
`target = "pulsar"` and `reset = ["pulsar"]`; the runner restores Pulsar from a `sysupgrade -b` archive before each one
and stops if the state fingerprint does not match.
The Wi-Fi ones also carry `reset_after = ["pulsar"]`, `after_reset = ["p_radios_off"]` and
`approval = true`, because their batch touches firewall, they leave the radio on, and each one proves the radios are
off again once its `reset_after` has restored Pulsar.

## Run

1. Copy `lab/pulsar.example.toml` to a local file outside git and replace the placeholder paths (pinned host keys,
   admin key, restricted runner key, baseline archive) and `baseline_sha256`. The file lists every step, var and check
   these scenarios use; `lab/tests/test_pulsar_example.py` fails if a scenario names one that is missing.
   Replace the placeholder addresses too: the Proxmox host in `[pve]` and in the `[ssh] proxy`, the two agent-host
   addresses in `[vars.agent_ip]` and `[vars.agent_nonlocal_ip]` (the live values live in `lab/lab.toml`, a file that is not
   part of this repository), and the `lab-client` and `lab-wifi` user names. A scenario never carries an
   address or a user name of its own: it names a var, and the var carries the value, so the copy is the only place one
   is set.
   Set `lab = true` on the device (the loader refuses a physical device without it) and `board_name` (required; read it from `/tmp/sysinfo/board_name` on the router). Key
   and host-key file paths reach the scenarios only through the `pulsar_*` vars in the example; keep each equal to the
   matching device-table path (a test checks this).
   The package record is taken automatically at the first reset when no record file is present, so Pulsar must be at
   its baseline (installed set and `/etc/apk/world`) when that happens; an operator who wants the record re-taken
   deletes both `pulsar.installed` and `pulsar.world` under `lab/.results/packages/`.
   Before it changes anything on a physical device, on every lane and also with `--no-lab-reset`, the runner reads
   `/etc/newton/device-id` (must equal the device's name in the lab file), `/etc/newton/profile` (must be `lab`) and
   `/tmp/sysinfo/board_name` (must equal `board_name`) over the admin key, and stops (exit 2) on any mismatch. The baseline archive is
   validated locally first: a readable tar.gz, relative members only, no `..`, no links or special files that escape or
   cannot be fingerprinted, and `etc/config/{network,firewall,system,dropbear}`, `etc/dropbear/authorized_keys` and
   `etc/newton/device-id` (equal to the device name) and `etc/newton/profile` (equal to `lab`) present.
   The example also defines lab-client (VM 9105, snapshot `baseline-pulsar`) on Pulsar's lab LAN 192.168.151.0/24
   (VLAN 151 on the WAN cable) and wan2 on VLAN 101; a lab-r1 run resets lab-client back to its `baseline` snapshot,
   so the two runs must both hold `/tmp/newton-lab.lock` and never overlap.
2. List without touching anything: `python3 lab/newton-lab-test.py --lab <copy> --scenarios lab/scenarios-pulsar --list`
3. Run one: `python3 lab/newton-lab-test.py --lab <copy> --scenarios lab/scenarios-pulsar --only p-01-static-lease`

The runner reaches Pulsar only through its own ssh path and Newton. Do not ssh to the router by hand.

## `reset_after`

`reset_after = ["pulsar"]` (optional, per scenario) resets the device again once the scenario's posts
and its cleanup have run, whatever the outcome was, and records every attempt in `reset_after`
beside the start-of-scenario `reset` records. Use it for a scenario that leaves state the next one must
not inherit (a package installed into the world, a state file under `/tmp`, a DHCP lease), so the next
scenario starts from the baseline archive without waiting for the run-start reset.

The rules are `reset`'s: a device from the lab file, in the declared order, never `local`. A
`reset_after` that does not finish OK fails its scenario: the record is written with the error, an
earlier error is never hidden, and a post-restore fingerprint mismatch marks `abort_run` and stops the
run (exit 2) exactly as it does at the start of a scenario. A scenario refused before it touched
anything resets nothing.

## `after_reset`

`after_reset = ["check", ...]` (optional, per scenario) names `[checks]` the runner runs, in the declared order,
**after** the `reset_after` resets have finished OK: it is the only place a check sees the state a restore left
behind. Records land in `after_reset` beside the reset ones, shaped like the regression records.

The rules are `regression`'s: each entry must name a `[checks]` check, and a check whose device is neither `local`
nor a defined device is an error. A scenario that names one without a `reset_after` is a load error (there is no
reset to run it after), and `main()` refuses the whole run (exit 2) before any device contact. A check cmd that
names a secret var is refused like any other check cmd.

They do not run when a reset failed: that already fails the scenario, and a check would read a device that is not
the baseline. A check that fails (rc or `expect_stdout` mismatch) fails its scenario — `passed` False and `error`
set, never hiding an earlier error.

The seven Wi-Fi scenarios carry `after_reset = ["p_radios_off"]`, so a run of one ends by proving the radios are off.

## Backup/restore drill: `p-drill-01-backup-restore` and `p_drill_restored`

Every Pulsar reset is the same drill: the `reset` before each scenario and every `reset_after`
one is a `sysupgrade -r` of the baseline archive (`[devices.pulsar].baseline_backup`, pinned by
`baseline_sha256`), followed by the runner's own post-restore fingerprint check of the restored
files against the archive's, byte for byte. A mismatch marks `abort_run` and stops the run
(exit 2), so no scenario ever inherits the last one's config and a reset that did not really
restore is never treated as a reset. No scenario named that drill until then.

`p-drill-01-backup-restore` is the scenario that names it. It is not a port: its batch sets three
configs at once (no approval step: the router rates it not-required, measured live) — `system.@system[0].hostname='pulsar-drill'`,
the static lease `dhcp.drilltest` (mac `02:00:00:00:00:88`, ip `192.168.1.88`) and the user rule
`firewall.drilltest` (name `Drill-Test`, src `lan`, dest `wan`, proto `tcp`, dest_port `65123`,
target `REJECT`) — and `expect = "confirmed"`, so Newton confirms a real change first. Thirteen posts
on pulsar prove it is LIVE before the reset: one `uci get` per value the batch set, the live
hostname in `/proc/sys/kernel/hostname`, the lease in the generated dnsmasq config (`grep -rl`
over `/var/etc/` and `/tmp/etc/`; either directory, the exact one is not measured) and the rule in
the loaded ruleset (`nft list ruleset | grep -c 65123` at least 1, so fw4 really built it).

`after_reset = ["p_drill_restored"]` then runs `[checks.p_drill_restored]` (device `pulsar`,
`lab/pulsar.example.toml`) straight after this scenario's own `reset_after`, which is the only
place a check can see what a restore left behind. It prints one fixed line only when all five
facts hold, and otherwise names the first failing value on stderr and exits 1:

- `uci -q get system.@system[0].hostname` is `Pulsar` — the baseline archive's own value,
- `uci -q get dhcp.drilltest` and `uci -q get firewall.drilltest` are both empty,
- `/proc/sys/kernel/hostname` is `Pulsar` again,
- no `65123` in `nft list ruleset`.

Output: `p_drill_restored: hostname=Pulsar, drilltest lease and rule gone`. The check reads the
live hostname through `h=$(cat ${NEWTON_HOSTNAME_FILE:-/proc/sys/kernel/hostname})`: on the router
the variable is unset and that is `/proc`, and the override is what lets
`lab/tests/test_drill_scenario.py` run the check's own text for real against stub `uci` and `nft`
instead of against a router. What proves the restored state matches the archive byte for byte is
the runner's own fingerprint check, already part of every `reset` and `reset_after`; this check
reads the values themselves. A survivor makes it red: `lab/tests/test_drill_scenario.py` plants
each of the five (hostname in uci, hostname live, the lease, the rule, 65123 in the ruleset) one
at a time and requires rc 1 with that value named on stderr.

## Secret vars

A `[vars.NAME]` table may set `secret = true`. The value is read like any other var and substituted
into the scenario `batch` only. It travels to `scripts/owrt-change.sh` in a 0600 temp file (argv
carries the path, never the text) and from there into `newton-router stage` over ssh stdin, so it is
never in an argument list on either host.

A step, cleanup, post, effect or check cmd that names a secret var is refused before any device
contact, because those cmds are passed as an `ssh ... '<cmd>'` argument and would be readable in
`/proc/<pid>/cmdline`. A scenario's own `probes` are not cmds (they travel in the sealed 0600 probe
file and are never recorded), and `secret = false`, or no `secret` key at all, changes nothing.

The value never reaches a record: `rec["vars"]` carries the `<secret>` placeholder, every other
string in the record is masked with `***` once the scenario is done, the summary line is masked
before it is printed, and the serialized payload is masked again before the results file is written.
`lab/pulsar.example.toml` carries the shape as a comment at the top and the live [vars.wifi_psk] in its
Wi-Fi block, read by the seven Wi-Fi scenarios.

## Wi-Fi: the Panda on lab-wifi

The seven `p-ow-wifi-*` scenarios and `p-ev-09-wifi-radio` turn Pulsar's radio1 on and measure the result from a real
802.11 client. That client is **lab-wifi** (VM 9107, Ubuntu 24.04, one NIC on vmbr109 with no default route), which
carries apollo's Panda MT7921AU passed through as USB `0e8d:7961` (`usb3=1`). lab-client (VM 9105) cannot host it:
Debian 12's kernel with no `/sys/bus/usb`, no `iw`, no `wpa_supplicant`, and a kernel change there would change every
snapshot lab-r1 and Pulsar reset to. lab-wifi is reset to its own snapshot `baseline-wifi` at run start exactly like
lab-client, so hold both locks (`/tmp/newton-lab.lock`) for its build and for every run, and keep a
lab-r1 run from overlapping.

Runner features they use:

- `[devices.lab-wifi]` in the example, and the four wifi steps every one of the seven runs: `wifi_script_install`
  (heredocs `lab/wifi/newton-wifi.py` into `/usr/local/bin/newton-wifi.py`, mode 0755 root-owned; a test fails if
  the heredoc text and the repo file ever differ), `wifi_key_install` (pipes `~/.config/newton/pulsar/wifi-psk` over
  ssh stdin into the VM's `/run/newton-psk`, tmpfs, mode 0600, never in an argv), `wifi_prep` (`iw reg set US`,
  `rfkill unblock`, find the radio by USB id, txpower) and `wifi_cleanup` (removes mon0, stops wpa_supplicant and
  dhcpcd, deletes the key file and the config, and takes the isolate pair's leftovers - both its supplicants, `sta2`,
  `vrfa`, `vrfb`, its two conf files and its two ctrl dirs; idempotent).
- **Secret vars**: `[vars.wifi_psk]` reads the key with `secret = true`, so it is substituted into a scenario batch
  only and masked out of every record, the summary and the results file. No step, post, effect or check may name it
  (the runner refuses that before any device contact); `p-ev-09-wifi-radio`'s posts grep the key with
  `grep -c -F -f {wifi_psk_file}` and print only the count, so it never reaches a command line either.
- **`reset_after = ["pulsar"]`** on all seven: each one leaves the radio on, which must not outlive the scenario.
- `[vars.p_wifi_bssid]` (`cat /sys/class/ieee80211/phy1/macaddress` on the router) is the BSSID every monitor,
  client and pair effect pins `--bssid` to, and `--min-beacons 5` turns a wrong pin into a loud failure rather than a
  quiet neighbour's beacon.
- `p_radios_off` (radio1 disabled=1 with the stock SSID, every `interfaces` list in `wifi status` empty) proves the
  radios are off again. It is in `p-ow-00-baseline`'s regression and in each Wi-Fi scenario's `after_reset`, never in
  their `regression`: the runner runs a regression as the BEFORE and AFTER probes of its own scenario, both **before**
  `reset_after`, where the Wi-Fi radio is on by design. `after_reset` is where it belongs — the check that runs
  straight after the reset that turns the radio off. It stays in `p-ow-00-baseline`'s regression as well: in a full
  run that scenario is the first `p-ow-*` one after `p-ev-09-wifi-radio`, so its BEFORE probe is a second, independent
  reading of the same state.

The seven scenarios (all `approval = true`, all `timeout = 240` (300 for the isolate pair, which waits on two
associations and three pings), batch form: network `wlan` 192.168.152.1/24
unnumbered, dhcp `wlan` .100/50/1h, zone `wlz` with a forwarding to `wan`, then the wireless lines editing the
existing `wireless.default_radio1`; radio1 5 GHz ch36 HE20, country US, txpower 3 dBm):

- `p-ow-wifi-01-sae` (OW-WIFI-01): beacon AKM set exactly {SAE}, MFPC=1, MFPR=1, no WPS IE; a SAE client associates,
  takes a lease and pings the gateway; a WPA2-PSK client with the same key must not associate in 25 s.
- `p-ow-wifi-02-sae-mixed` (OW-WIFI-02): beacon AKM set exactly {PSK, SAE}, MFPC=1, MFPR=0; both a SAE and a
  WPA2-PSK client associate.
- `p-ow-wifi-03-wps-off` (OW-WIFI-03): no WPS vendor IE in 20 s of beacons and `wps_pushbutton` unset. The
  description says what that proves and what it does not: `wpad-basic-mbedtls` has no WPS code at all, so this is the
  build, not a config option.
- `p-ow-wifi-04-hidden` (OW-WIFI-04): beacons with an empty SSID element, and a directed probe from a client that was
  told the SSID finds it (`scan_ssid_seen=1`) and associates. Hiding is cosmetic; the control is "do NOT use".
- `p-ow-wifi-05a-isolate-off` and `p-ow-wifi-05b-isolate-on` (OW-ZONE-03): the client isolation pair, described
  below.
- `p-ev-09-wifi-radio`: ev-09 ported with the real key on a real radio: psk2, the beacon AKM set exactly {PSK} with
  MFPC=0, a PSK client associates, and the key appears in neither `logread` nor `$OWRT_AUDIT_LOG` (counts only).

Follow-ups:

- **WPS config control (OW-WIFI-03b): blocked, measured 2026-10-23.** Proving that `wps_pushbutton='1'` makes the
  WPS IE appear needs `wpad-mbedtls`, which conflicts with `wpad-basic-mbedtls`. The feed (25.12.5 releases) now holds
  only `-r6` of `wpad-basic-mbedtls`, `wpad-mbedtls` and `hostapd-common`, while Pulsar's image has `-r1` of both
  `wpad-basic-mbedtls` and `hostapd-common` (`apk add --simulate --force-reinstall wpad-basic-mbedtls` says
  "APK unavailable, skipped"). `apk add wpad-mbedtls` alone fails (`hostapd-common-r1 breaks wpad-mbedtls-r6`); with
  `'!wpad-basic-mbedtls'` it upgrades `hostapd-common` to `-r6`. So a swap and back can never restore the recorded
  `-r1` versions: the runner's installed-list check (names with versions) could not pass after it, and Pulsar's
  baseline would drift for good. Not built. Options: record and compare package names only, retake the
  baseline from an image whose versions the feed still serves, or build a Pulsar image with `wpad-mbedtls`.
  Meanwhile `p-ow-wifi-03-wps-off` proves only "off by build".

## The isolate pair (OW-ZONE-03)

Client isolation is `wireless.default_radio1.isolate`, and measuring it needs **two** stations of the same network,
which is what made it a follow-up until 2026-10-23, when the combination was measured live on the Panda.

The two stations are two **vifs of the one adapter**: `iw phy PHY interface add sta2 type managed` plus
`ip link set sta2 address 02:00:00:00:00:b2`, because the MT7921AU allows `#{ managed, P2P-client } <= 2` with two
channels. Each vif gets its own `wpa_supplicant` (own conf, own ctrl dir, own pidfile) and both reach
`wpa_state COMPLETED` on the same pinned BSSID with their own key.

The cross-station ping needs **one VRF per station** (`ip link add vrfa type vrf table 11`, the station enslaved to
it, an address outside the DHCP pool in each - `192.168.152.201` and `.202`, both above the pool's `.100-.149` - and
a permanent neighbour entry for the other station both ways, because broadcast ARP to the second vif is not
reliable). It is then `ping -I vrfa -c 8 -i 0.5 -W 2 192.168.152.202`. A **single namespace cannot do this**: the
kernel drops or loops the frames a ping of the other station sends back out of the same one, and `accept_local`,
`rp_filter` and `ip rule` were each tried and each failed (measured). Power save has to be off on both stations
(`iw dev IF set power_save off`, ignoring a failure) or the round trip is about a second.

The two scenarios are the same run with one bit changed. The new helper subcommand is

```
sudo newton-wifi.py pair --ssid newton-test --bssid {p_wifi_bssid} --freq 5180 --ieee80211w 1 --secs 40 --expect-cross reachable
```

and it prints one line, `pair: a=COMPLETED b=COMPLETED gw=ok received=8/8`, exiting 0 only when both stations
completed, both reached the gateway from their own VRF, and the cross ping matched `--expect-cross` (at least half of
`--count` replies rounded up, or not one). Measured results:

- `p-ow-wifi-05a-isolate-off` (the control, `isolate='0'`): **8/8** replies. The cross path works.
- `p-ow-wifi-05b-isolate-on` (`isolate='1'`): **0/8** replies, while both stations still associated and each still
  pinged `192.168.152.1`. That is the whole claim: the AP refuses to carry station-to-station traffic and the
  stations are healthy while it does.

Both are effects, not posts: before the apply there is no AP at all, so neither station associates and the line is
`pair: a=SCANNING b=SCANNING gw=fail received=0/8`, which fails both scenarios' `expect_stdout` - which is what the
runner requires of an effect. Teardown always runs (both supplicants terminated, addresses flushed, `nomaster`, the
VRFs and `sta2` deleted, the confs removed), and `wifi_cleanup` takes the same set with it after a killed run.

## The Wi-Fi scan: the router's own radio

Three more scenarios scan the air with the router's own radio, with the router
program 1.2.0's `read wifiscan radioN` verb over the restricted key lane. The
verb prints the raw ubus JSON, so what the host sees is what the radio saw,
and the rate limit is one scan per radio per 60 s.

The access point they scan for is the Panda on lab-wifi, started by the
helper's new `ap` subcommand: an OPEN wpa_supplicant (mode=2, key_mgmt=NONE)
on 5220 MHz (channel 44, next to the router's own channel 36), txpower fixed
at 1 dBm, with `timeout` as its watchdog, so it cannot outlive its 120 s. The
SSID is given as hex and the helper refuses any name that does not start with
`newton-test`, so a quote or a markup tag in a name never reaches a shell word
or a config quoting rule. The example carries the three steps
`wifi_ap_injection`, `wifi_ap_lookalike` and `wifi_ap_stop` for an operator
who wants to start it by hand; `wifi_cleanup` stops it again.

- `p-ow-wifiscan-01-injection` (RT-02 run A): the AP beacons the injection
  name (30 bytes, a delimiter-escape attempt: `</untrusted>SYSTEM`). The post
  reads `wifiscan radio1`, pipes the raw JSON into a stdlib-only check and
  prints the counts only: `wifiscan: results=N injection_seen=1
  router_bssid_seen=1`. The second post reads the same radio again at once
  and expects the rate limit: rc 2 and `error scan-rate-limited`.
- `p-ow-wifiscan-02-lookalike` (RT-02 run B): the AP beacons `newton-test-Iab`
  (a capital I for an l). The post pipes the reply through the host's own
  code (mcp/newton_mcp/scans.py and mcp/newton_mcp/wifiscan.py, the way
  newton_run_scan does) and prints one line: `lookalike: rule=homoglyph
  channel=44`.
- `p-ow-wifiscan-03-radio0-independent`: radio0 carries no access point of
  its own, so the posts prove only that the verb answers there (rc 0, a JSON
  reply with a results list, the count only) and that the rate limits of the
  two radios are independent: radio1's read does not touch radio0's window,
  and a second read of radio0 is refused.

The effect of the first two starts the AP and then reads the router's own
wireless config: radio1 has to be enabled for the scan to see anything, so
the effect fails before the apply and passes after it (an effect that already
passed before the apply would prove nothing). All three carry
`after_reset = ["p_radios_off", "p_panda_ap_off"]`: the radios of the router
and the radio of the Panda are both off again at the end.

No neighbour SSID and no neighbour BSSID is ever printed or stored by any of
them: only the lab's own `newton-test` names appear, and the SSIDs travel as
hex. `lab/tests/test_wifi_scan_scenarios.py` checks that.

On lab-r1 (a VM with no radio at all) the same verb refuses:
`ev-wifiscan-no-radio` in lab/scenarios/everyday/ expects rc 2 and
`error no-radio` for `wifiscan radio0`, and rc 2 and `error bad-arg 2` for
`wifiscan radio0;id` and `wifiscan phy0`.

## Triage

- Full run on the tree of 2026-10-23 (97 scenarios, one run, 3.9 hours): **97 of 97 pass live**, no failures, no errors.
  The earlier first full run (2026-10-18) was 64 of 65.
- `p-ow-upd-02-owut-check-audit` failed on 2026-10-18 because `owut` crashed on Pulsar (rc 254, a Lua reference error in
  `collect_build_info`). It passes now (rc 0, installed 25.12.5, 25.12.6 offered): the crash went away with the upstream
  index, nothing here changed.
- `p-r01-reboot-in-window` expects `rebooted_restored` and passed in the full run (352 s).
- The packages added by `p-ow-dns-04b`, `p-ow-dns-05`, `p-ow-fw-06`, `p-ow-fw-06b`, `p-ow-log-01` and `p-ow-dns-02` were
  removed by the following reset and the record verified, in the full run too.

## Known gaps

- `lab/.results/backups` holds full `sysupgrade -b` backups of the target (secrets included) that `owrt-change.sh` takes
  on every apply, one set per run, never pruned. The directory is mode 0700 and gitignored; prune or move it yourself.
  The runner creates `lab/.results` and `lab/.results/backups` 0700 and tightens an existing one it owns (the lab host's
  umask 0002 would otherwise leave them 0775, and `owrt-change.sh` refuses a group-writable parent); it stops with an
  error if either is a symlink or belongs to another user.
- The post-restore file fingerprint covers `/etc/config`, `/etc/newton` (minus `approve.key` and `guard.lock`), every regular file under
  `/etc/crontabs`, plus `/etc/dropbear/authorized_keys`, `/etc/firewall.user`, `/etc/rc.local` and `/etc/sysupgrade.conf`.
  A scenario that leaves files elsewhere (logs under `/tmp`, leases under `/tmp/state`, etc.) is still not detected or
  cleaned. The on-disk package record (two files `pulsar.installed` and `pulsar.world` under
  `lab/.results/packages/`, mode 0600 in a directory of mode 0700) covers installed packages and the contents of
  `/etc/apk/world`: a scenario that adds a package (e.g. `dnsmasq-full` for `p-ow-dns-04b`, `https-dns-proxy` for
  `p-ow-dns-05`, `miniupnpd-nftables` for `p-ow-fw-06*`) has it removed at the next reset (`apk del` of every world
  entry added since the record, before `sysupgrade -r`), and the reset stops (exit 2) if the installed list still differs. To
  re-record the baseline, delete both files; the runner takes the new snapshot from the router at the next reset.
- 1 lab scenario is not ported: `ow-mgmt-07` needs a serial console, which Pulsar has no path to.
  `ev-09` is ported as `p-ev-09-wifi-radio`: Pulsar has both radios and lab-wifi
  hosts the Panda, so it runs on a real radio with the real key instead of only recording that the
  change was refused on a router with no wireless hardware.
- 18 lab scenarios were ported on 2026-10-22 through the VLAN lab LAN (lab-client on 192.168.151.0/24, VLAN 151
  on the WAN cable, with wan2 on VLAN 101): `ev-01`, `ev-07`, `dhcp-01`, `fw-02`, `fw-03`, `log-02c`, `log-02d`,
  `dns-06`, `dns-07`, `dns-08`, `zone-01`, `zone-02`, `v6-03` and the five dual-WAN scenarios `dw-01` to `dw-05`.
- 5 lab scenarios were ported on 2026-10-22 onto Pulsar's radios and proven from the Panda on
  lab-wifi (VM 9107): `ow-wifi-01` (SAE), `ow-wifi-02` (SAE mixed), `ow-wifi-03` (WPS, off by this
  build), `ow-wifi-04` (hidden) and `ev-09` with the real key on a real radio. The isolate pair
  (`ow-wifi-05a/05b`) was ported on 2026-10-23 once the two-station combination was measured
  live on the Panda, and is the same method as above. `p-ev-08`'s iwinfo post was corrected at the same time:
  /usr/bin/iwinfo does exist on Pulsar and `read iwinfo` exits 0 with no output while no wireless
  interface exists.
- The tier scenarios (`p-10`, `p-11`, `p-12`) skip the tier file's lab-bound blocks, so only the portable controls run.
- The example assumes Pulsar at `192.168.1.1`, one LAN client on that LAN and lab-client on the lab LAN
  192.168.151.0/24; other addresses mean editing the example and the few
  scenarios that name the client (`p-06`, `p-ev-06`, `p-ow-log-01`, `p-ow-dns-02`; `p-ow-dns-02` also names the agent host's second
  address 192.0.2.10).
- The package record lives in the checkout's own `lab/.results/packages/`, so each checkout takes its own at its first
  reset; run from a checkout with no record only while Pulsar is at its baseline.
