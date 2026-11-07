# 06 — OpenWrt Adapter Specification (Platform #1)

## 1. Targets

| Item | Value | Status |
|---|---|---|
| OS | OpenWrt **25.12.x** (25.12.0 released early March 2026; `apk` replaced `opkg`; dropbear 2025.89; kernel 6.12) | [V-13] |
| Old branch | 24.10 security support ended September 2026 — don't build against it | [V-13] |
| DUT | Asus **RT-AX1800S v2** (same hardware/firmware as RT-AX57M: MediaTek MT7981B, 256 MB RAM, 128 MB SPI-NAND, MT7531 switch; OpenWrt support since 25.12.0) | [V-29], model per [A-01] |
| DUT console | UART 3.3 V, 115200 8N1, pinout silkscreened — **do not connect VCC** | [V-29] |
| Twin | OpenWrt 25.12.x x86-64 VM on Proxmox (same release as DUT), plus containerlab `openwrt` kind later [V-25] | — |
| Future prod | Whichever router runs the home dual-WAN (currently the GL-MT3000; per your plan possibly the second RT-AX1800S v2 — which would make the DUT an exact hardware twin of prod) | [A-06] |

## 2. Access paths (priority order) [ADR-016]

1. **SSH restricted key to one on-router program** (`/usr/libexec/newton/newton-router`) for the change
   protocol, reads, hostnames, backups, status and abort. Key entry:
   `restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,command="/usr/libexec/newton/newton-router --caller=<label> --role=<change|read>"`
   [V-18, LVR-04]. The program holds a closed grammar of 24 subcommands (design 3.4); every argv class
   is anchored; no request, stdin or router value becomes shell code (design 3.1). The root password SSH
   lane stays for the maintainer and the lab (direct mode).
2. **rpcd JSON-RPC over HTTP(S) at `/ubus`** with a dedicated, ACL-scoped user. Second door, later release
   (design section 11); not built for 1.0. Same path LuCI uses; structured in and out; device-enforced
   coarse authorization [V-17]. HTTPS availability on the default 25.12 image is recorded at LVR-05.
3. **Serial console** (OOB) via ser2net on the lab controller — lab/recovery only.

### 2.1 Device prerequisites (human-performed in P0 — these are leash items)

- Dedicated **mgmt port**: move one LAN port out of `br-lan` into interface `mgmt` (static IP on the
  mgmt subnet), its own firewall zone `mgmt` with input ACCEPT only from `newton-ctl` for 80/443/22,
  forward REJECT. NEWTON's changes to this interface/zone are CRITICAL (L2); a leash code on the router
  refuses them (design 5.2 `mgmt-interface`, `mgmt-zone`).
- System user `newton` with no login shell (its restricted SSH key lives under `/var/lib/newton/keys/`;
  setup adds it to `/etc/dropbear/authorized_keys`) [V-17, V-18]. For 1.0 Newton does not need an rpcd
  login or ACL user (the rpcd door is a later release; not yet run on a router, gate G0).
- The program at `/usr/libexec/newton/newton-router`, the helper at
  `/usr/libexec/newton/newton-safe-apply`, the guard at `/usr/libexec/newton-guard`, the guard init at
  `/etc/init.d/newton-guard`, `/etc/newton/{device-id,profile,zones,approve.key}`, and `/etc/dropbear/authorized_keys`
  all persist through upgrades (design 2.3; added to `/etc/sysupgrade.conf`) [V-17].

### 2.2 Restricted SSH key line (illustrative; see [V-18, LVR-04])

```
# /etc/dropbear/authorized_keys  (append, one line per agent)
restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,command="/usr/libexec/newton/newton-router --caller=newton-agent --role=change" ssh-ed25519 AAAA<rest of the setup-generated key> newton-router-newton-agent
```

`<label>` matches `^[a-z][a-z0-9-]{1,31}$`; `<role>` is `change` or `read`. Setup writes the line; a
client cannot. The forced command is the one and only command the key can run (design 2.4, 8.3). The
plain Newton key and any of the maintainer's personal keys on root are removed by `swap-key` (8.3) under a 90 s
dead-man switch; the maintainer's root password, LuCI and the console stay.

### 2.3 Approvals on the router (closes the "ACL can't write mgmt" point)

The program, not an ACL, owns every per-section decision. `seal` classifies the staged change against
the design's leash codes (design 5.2: `mgmt-interface`, `mgmt-zone`, `mgmt-config`, `wan-zone`,
`zone-exposure`, `forwarding-mgmt`, `wan-forwarding`, `wan-redirect`, `wan-rule`, `defaults-accept`,
`exec-include`, `firewall-type`, `section-unidentified`, `exec-option`, `path-option`, `exec-config`,
`unknown-package`, `upnp-on`, `ntp-server-open`, `mgmt-route`, plus `profile-prod`); when the profile
is `prod` or any code fires, the router demands an HMAC token bound to its own digest of device,
session, base, diff, probes and T (design 5.4, 5.5; ADR-008 amended by ADR-016). There is no per-config
ACL scoping: scoping is the program's job, finer than the rpcd ACL the 1.0 design does not use
(`rpcd-mod-file`, `uhttpd-mod-ubus`, ACL roles and `/usr/share/rpcd/acl.d/` become relevant again with
the rpcd door release). For 1.0, the live checks in design 9.4 are not recorded as run on a router.

## 3. Read surface (getters)

| Getter | Source | Untrusted fields | Notes |
|---|---|---|---|
| `facts` | `system board`, `system info` | hostname | release, target, board name, uptime, memory |
| `interfaces` | `network.interface dump` | — | **effective** proto/up/addresses vs configured |
| `devices` | `network.device status` | — | ports, link state, DSA |
| `routes` | `network.interface dump` routes; `ip -j route` via shim | — | [LVR-11] |
| `firewall_config` | uci `firewall` | names/comments | redacted, structured |
| `firewall_effective` | `fw4 print` (rendered) / `nft -j list ruleset` via shim | comments | needed for widening detection [LVR-11] |
| `dhcp_leases` | `/tmp/dhcp.leases` (file ACL) | **hostname, client-id** | attacker-controlled |
| `wifi_status` | `iwinfo info/assoclist` | station data | DUT only (twin has no radios) |
| `wifi_scan` | `read wifiscan radioN` (ubus `iwinfo scan` via `phyname`; router program 1.2.0) | **SSID, BSSID** | attacker-controlled; active RF: one scan per radio per 60 s; scan-class consent; with an AP up, clients lose about 10 s of link (measured 2026-10-24) |
| `logs` | `logread` via shim (tail, filtered) | **every line** | paginate; cap |
| `services` | `service list` | — | — |
| `packages` | `apk list --installed` via shim | — | `apk`, never `opkg`, on 25.12 [V-13] |

All outputs pass through redaction then the untrusted envelope (`04`).

## 4. Change ops (structured; the agent never sends uci CLI text)

```json
{"op": "set",      "config": "network",  "section": "guest", "option": "proto", "value": "static"}
{"op": "add",      "config": "firewall", "type": "zone", "name": "guest"}
{"op": "delete",   "config": "firewall", "section": "guest_wan_fwd"}
{"op": "add_list", "config": "dhcp",     "section": "guest", "option": "dhcp_option", "value": "6,10.20.0.1"}
{"op": "del_list", "config": "dhcp",     "section": "guest", "option": "dhcp_option", "value": "6,10.20.0.1"}
{"op": "reorder",  "config": "firewall", "sections": ["...ordered section ids..."]}
```

Rules:
- Anonymous sections (`@rule[3]`) are resolved to stable section IDs **at plan time** and pinned in
  the plan; drift → STALE at apply.
- New sections get explicit names (`newton_<shortid>` if the agent doesn't name them) so later plans
  can reference them deterministically.
- Values are validated against per-option schemas before lint (types, ranges, enums, address grammar).
- Secret placeholders are legal only as `set` on their original path (= keep) [ADR-007].

## 5. Apply pipeline

Two candidate mechanisms. **Spike both in P0** (SPK-1) and decide in ADR-006.

### Option A — rpcd native apply/confirm [V-14, V-16; LVR-01, LVR-02, LVR-13]
1. `session.login` → session **S1**.
2. Stage ops via `uci set/add/delete/…` with S1.
3. `uci changes` with S1 must equal the plan's ops (else abort).
4. `uci apply {rollback: true, timeout: T}` with S1 → commits + reloads with rollback armed.
5. New login → **S2** (new TCP/HTTP connection) → EV-01 mgmt reachability, then EV-02…08.
6. Pass → `uci confirm` (which session it requires: [LVR-01]). Fail → `uci rollback` or let T expire.
- LuCI's Lua model enforces a minimum of 90 s for this timeout [V-16]; rpcd's own minimum is unknown.
- **Known gap (hypothesis):** rollback state likely lives in RAM, so a reboot inside T may keep the
  new config [LVR-02].

### Option B — NEWTON guard (device-side, reboot-safe) [ADR-006]
1. `newton.arm {txn_id, timeout_s}` (rpcd exec plugin [LVR-06]):
   - copy `/etc/config/*` → `/etc/newton/lkg/<txn_id>/` (on flash; check free space first);
   - write `/etc/newton/pending` = `{txn_id, deadline_uptime}`;
   - start a detached timer process keyed to `/proc/uptime` (not wall clock).
2. Stage ops with S1; commit; trigger reload (`reload_config` / `uci apply` without rollback).
3. S2 verification as in Option A.
4. `newton.confirm {txn_id}` → delete `pending`, stop timer, prune LKG (keep last 5).
5. Timer expiry → restore LKG, reload, write `/etc/newton/last_revert` with reason.
6. **Boot hook** (`/etc/init.d/newton-guard`, ordered before network [LVR-07]): if `pending` exists →
   restore LKG before services start, log, clear `pending`.

Option B is the expected authority (reboot-safe, same mechanism usable on Linux+FRR later); Option A
may be layered for defense in depth. Risks of B: flash wear (tiny files, acceptable), guard bugs
(hence its own test suite in `device/openwrt/newton-guard/tests`), LuCI edits during an armed window
get wiped by restore (documented; guard records the pre-restore config for forensics).

### Timeout sizing
`T = 2 × (measured worst-case reload time for touched services + verification budget)`, min 60 s,
max 600 s. Wi-Fi reloads are the slow case; measure on the DUT [LVR-12].

## 6. On-device guard (`device/openwrt/newton-guard/`)

| File | Purpose |
|---|---|
| `/usr/libexec/newton-guard` | timer/restore logic (POSIX sh or ucode; no network calls; no eval of inputs) |
| `/etc/init.d/newton-guard` | boot-time restore if `pending` present; ordered before rpcd, dropbear and netifd (S09; measured at about 8 s uptime on lab-r1; design 6.6) |
| `/etc/newton/` | `lkg/<txn>/`, `pending`, `failed`, `last_revert`, `guard.log` (rotated) |

Wired flow (ADR-013 open point closed by ADR-016): the program arms the guard with `newton-guard arm <SID> <T+30>`
just before it calls `ubus call uci apply` (rpcd's apply). rpcd confirms first, the guard second (design 6.3).
`abort` settles both (design 6.4). `status` reads guard state and config hashes: `post` vs `base` (design 6.5).
Guard window bound is 600 s on the program side (T 60..600), guard's `valid_timeout` upper bound 900 s
(RD10; design 6.1). Caller protocol and command grammar are in `device/openwrt/newton-guard/README.md`;
the program (`device/openwrt/newton-router/newton-router`) is the only caller in production. The guard runs
at boot (S09) before rpcd, dropbear and netifd (closed on lab-r1; design 6.6); not recorded as run on
the production-class router. The rpcd exec plugin path is moot for 1.0 (LVR-06); it returns with the rpcd door
release (design section 11).

## 7. Effect verification checks

| ID | Check | Method |
|---|---|---|
| EV-01 | Mgmt reachability from a **new** session | new login + `system board` within budget |
| EV-02 | Firewall renders and loads | `fw4 check` passes [V-19]; rendered ruleset diff vs pre-change |
| EV-02b | No widening | rendered-ruleset diff contains no new bare `accept` or broadened match not present in the plan's intent |
| EV-02c | Change actually loaded | rendered ruleset differs from pre-change exactly where expected (catches "atomic reject kept old firewall") [V-06] |
| EV-03 | Interfaces effective | effective proto == configured; expected addresses; up [V-06] |
| EV-04 | DHCP works | probe on the segment gets a lease in range |
| EV-05 | DNS works | probe resolves via router |
| EV-06 | Intent tests | reachability/isolation/port-forward assertions from probes (`09`) |
| EV-07 | Wi-Fi | radio up, SSID beaconing (DUT only) |
| EV-08 | Services | expected services running after reload |

## 8. Semantic linter (runs before twin/live) — rules derived from [V-06] + leash

| Rule | Detects | Severity |
|---|---|---|
| OWRT-L01 | Port match on a protocol that can't carry ports (silently dropped → widened rule) | error |
| OWRT-L02 | `proto all` (or wildcard) combined with ports | error |
| OWRT-L03 | Zone `any` used as wildcard (only `*` is a wildcard) | error |
| OWRT-L04 | List-valued redirect match options that fw4 requires as scalars (`src_ip`, `src_port`, `src_dport`, `dest_ip`, `dest_port`) | error |
| OWRT-L05 | Protocol tokens nft can't resolve (e.g. `ipcomp`, `l2tp`, `vrrp`) or negated protocols → whole ruleset rejected | error |
| OWRT-L06 | `MARK`/`DSCP` targets missing their value options | error |
| OWRT-L07 | `NOTRACK` without a named source zone | error |
| OWRT-L08 | Zero-padded IPv4 octets; malformed IPv6; out-of-range/descending ports | error |
| OWRT-L09 | Interface proto whose handler package isn't installed (e.g. `wwan`) | warn + EV-03 |
| OWRT-L10 | Conntrack helper targets referencing modules not loaded (atomic reject) | error |
| OWRT-L11 | WAN exposure (L3) | CRITICAL |
| OWRT-L12 | Touches mgmt interface/zone/route (L2) | CRITICAL |
| OWRT-L13 | Secret placeholder used off its original path | LEASH_VIOLATION |

Each rule ships with a bad fixture, a good fixture, and a test. Then measure which of them `fw4 check`
alone would have caught on the DUT [LVR-10] — expectation: the widening cases pass `fw4 check`, which
is why the linter exists. (Re-implement these from the documented behavior; check the uapi project's
license before reusing any code.)

## 9. Packages and firmware

- `apk` only on 25.12 [V-13]. Package install/remove = HIGH (L4): check free flash, prefer adding
  packages via image builder / attended sysupgrade (`owut`, ASU are present on 25.12 [V-13]) for
  persistence — firmware operations are human-only in v1 (L5).

## 10. Recovery ladder (lab DUT)

| Step | Trigger | Who/what |
|---|---|---|
| R1 | Verification fails | NEWTON immediate rollback |
| R2 | Controller lost / confirm withheld | Device-side timer restore |
| R3 | Reboot inside window | Guard boot hook restore (Option B) |
| R4 | Still unreachable | Serial console: inspect, `newton-guard restore`, or manual fix |
| R5 | Config-level brick | Failsafe mode via serial (key prompt during boot) [LVR-08], restore config |
| R6 | Config beyond repair | `firstboot` + re-provision NEWTON prerequisites from a script |
| R7 | Firmware broken | Re-flash: initramfs/sysupgrade path, or Asus Firmware Restoration rescue mode [V-29, LVR-09] |
| R8 | Bootloader-level | U-Boot serial menu (bootlog shows a "write to flash via serial" option) [V-29, LVR-09] |

R1–R3 are automatic. R4–R6 are automated in P5 for the lab profile only. R7–R8 stay human.

## 11. Twin parity

| Domain | Twin (x86-64) | DUT |
|---|---|---|
| Firewall / NAT / zones | ✓ parity | ✓ |
| DHCP / DNS (dnsmasq/odhcpd) | ✓ | ✓ |
| Routing / dual-WAN failover logic (netifd metrics + health script) | ✓ (with lab-isp WANs) | ✓ |
| DSA switch ports / VLAN on ports | ✗ different hardware | ✓ DUT only |
| Wi-Fi radios | ✗ | ✓ DUT only |
| Reload timings | not representative | measure on DUT |

Rule: plans touching DUT-only domains skip twin-first and require OOB-healthy (lab) or approval.

## 12. OpenWrt LVR register (closed by tests; see `12`)
LVR-01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13.

## 13. Test fixtures to capture in P0/P1
Recorded rpcd responses for every getter (twin + DUT), `uci show` dumps with secrets (kept out of git;
generate synthetic equivalents for CI), rendered rulesets before/after canonical changes, `logread`
samples, DHCP lease files with injection payloads (from probe hosts), console boot logs.
