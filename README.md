<p align="center">
  <img src="docs/assets/newton-banner.svg" width="820" alt="Newton, network engineer for AI agents. Change a router. Prove it. Roll back if it broke.">
</p>

# Newton

**Change a router. Prove it. Roll back if it broke.**

Newton lets an AI assistant like Claude Code set up and change your network for you: routers, VLANs, Wi-Fi, firewall
rules, port forwards, DHCP, DNS and dual-WAN. It is the safe way to let the AI do the work. On the default setup every change is shown to
you first and needs your approval, unless you gave a scoped grant or set the router to lab (see Approvals). It arms an undo timer on the router, so it undoes itself if something breaks, and it is only kept after a
fresh connection proves your network still works. In the no-install mode that timer lives in the router's RAM, so a
router that reboots in the middle of a change keeps the change.

Newton is an operational skill for an AI agent plus an MCP server (`newton-mcp`). Both speak the same change protocol, so
any MCP-capable agent can use it: Claude Code, Codex, OpenCode or any MCP client.

Newton has two modes. In the **installed** mode the changes run over SSH. In the **no-install** mode Newton puts
nothing on the router but one limited web-interface user, and the same protocol runs over the router's own web API.

The change protocol is the whole product. The agent proposes a `uci batch`; Newton stages it, shows the diff, applies it under a rollback timer (60 to 600 seconds), verifies over **new** SSH connections that management and the network still work, and confirms only after three consecutive passing rounds. If anything fails, the router reverts on its own. The rollback timer lives on the router, so it still fires if the agent's session dies. That is the **installed** mode.

In the **no-install** mode the writes go over HTTPS, pinned by the certificate the setup read over the admin lane. The
undo is OpenWrt's own rpcd timer (in the router's RAM), and a change is confirmed only when every mandatory check
passes and the router's values read back as the staged ones.

## What Newton puts on your router

An OpenWrt router works in one of two modes. The no-install mode is the default for a new OpenWrt
router; the installed mode puts Newton's own program on the router. The owner picks the mode with
`sudo -u newton /usr/local/bin/newton-router-setup <device> no-install` or
`sudo -u newton /usr/local/bin/newton-router-setup <device> install`, and both
modes are shown side by side, in plain words, before the router is touched.

**no-install:** Newton puts nothing on the router except one web-interface user. Every change uses OpenWrt's own undo timer. Limit: if the router reboots or its web service restarts while a change waits for confirmation, the change stays. Limit: whoever steals Newton's router password could take an interface down, restart Wi-Fi, kick a device off, or store files in /etc/luci-uploads, without your approval. Newton applies only DHCP static leases and DNS entries itself; every other change is a script you approve and run.

**installed:** Newton puts a program on the router: a small set of shell scripts (6 files, about 210 KB), no packages and no compiled code. Newton's key can run that program and nothing else, so the agent never gets a root shell. If a Newton change is still waiting for confirmation at boot, the guard puts the last good settings back, so a reboot cannot leave that change stuck. More checks can run, and fewer changes need a script. uninstall removes Newton's program and key; it keeps the guard's saved settings and the rest of /etc/newton (its lock and log), the program directory, the WAN-health settings in /etc/config/newton_wanhealth, the keys from before swap-key and the sysupgrade file: the saved settings and the copy of your keys are what you restore by hand.

The no-install mode is **not** as safe as the installed mode. Its rollback is OpenWrt's own, the
same one LuCI uses, and Newton only applies the changes that are acceptable if they stay. The
installed mode keeps a guard on the router's own flash, so a reboot cannot leave a change stuck.

### The installed mode, in detail

This is exactly what the installed mode puts on your router, and what protects you. The install
prints the same text on your terminal before it asks you to agree:

```text
What Newton puts on your router

Newton's executable code is a small set of POSIX shell scripts; it also writes the configuration and service entries listed below.
No package is installed and nothing is compiled: about 210 KB of shell in 6 files.

  /usr/libexec/newton/newton-router     146 KB  the program Newton talks to
  /usr/libexec/newton/newton-safe-apply   20 KB  the change helper
  /usr/libexec/newton-guard              31 KB  the rollback guard
  /etc/init.d/newton-guard               525 B  starts the guard at boot
  /usr/libexec/newton/newton-wan-health   11 KB  the dual-WAN health check
  /etc/init.d/newton-wan-health          641 B  starts the health check

It also writes the device name, the profile and the zones under /etc/newton
(and, once you pick an approval passphrase, the approval key), the WAN-health
settings in /etc/config/newton_wanhealth, the boot links
/etc/rc.d/S09newton-guard, /etc/rc.d/S95newton-wan-health and
/etc/rc.d/K10newton-wan-health, and
13 lines in /etc/sysupgrade.conf, so a firmware upgrade
keeps them. The guard service runs at boot; the WAN-health check stays idle
until you set newton_wanhealth.main.enabled=1. One more line goes into
/etc/dropbear/authorized_keys, but the install does not write it: swap-key
or add-key does.

Why: the rollback has to survive a reboot or a cut link, so it lives on the
router; and Newton's key may run Newton's program and nothing else.

What protects you:
  - on the default prod profile every change needs your approval, and Newton
    only reads until you give one;
  - a router you set to lab applies changes without asking, except the ones
    Newton always asks about. Among them: SSH (dropbear), the web interface
    (uhttpd), rpcd, a users or keys config, the management interface or zone,
    opening more to the WAN, and options that run commands or write files
    (22 rules in all, in the router program's leash). The inventory entry
    has to say lab = true as well, or every change still needs your
    approval;
  - the guard keeps the last good settings on the router's own flash, and if a
    Newton change is still waiting for confirmation at boot, it puts them back;
  - the agent never gets a root shell through Newton's restricted key: once
    swap-key or add-key has written it, that key can run Newton's program and
    nothing else. Until you run swap-key, every key already on the router
    stays as it is. The setup tool itself logs in as root with your password
    or your admin key, when you run it; the agent never gets that login.

The trade-off: your router runs Newton's code, so it has to be kept in step with
Newton: run 'sudo -u newton /usr/local/bin/newton-router-setup <device> upgrade'.
'sudo -u newton /usr/local/bin/newton-router-setup <device> uninstall' removes
the program, the guard, the boot links, the config files, EVERY Newton key line
on the router for every host and label (including the key the Newton server
itself uses), and the sysupgrade lines. The run prints each removed key with its
restore command; after a reinstall, restore each one, on the Newton host that holds that
key, with
'sudo -u newton /usr/local/bin/newton-router-setup <device> add-key <label> <role>'.
On purpose it keeps the guard's saved copies of your settings
(/etc/newton/lkg and /etc/newton/quarantine) and the rest of /etc/newton
(the guard's lock and log), /usr/libexec/newton, the WAN-health settings file
/etc/config/newton_wanhealth, the copy of your keys from before swap-key,
/etc/dropbear/authorized_keys.newton-prev, and the /etc/sysupgrade.conf file.
The Newton lines go out of that file; the file itself stays, empty when the
install created it. The copy of the keys holds the key line swap-key took
out; if you still want that key to log in, copy the line back first. To
remove those by hand:
  rm -rf /etc/newton /usr/libexec/newton /etc/config/newton_wanhealth /etc/dropbear/authorized_keys.newton-prev
and delete /etc/sysupgrade.conf once you have checked that none of your own
lines are left in it.
The run-time files in /tmp/newton and /tmp/owrt-safe-apply.lock are in memory and go at
the next reboot. The uninstall stops the WAN-health check first, and its
restore removes the WAN-health run-time state in /var/run/newton-wan-health
(every *.state file and all_down.flag); the directory itself stays, empty.
```

## Get started

Paste this into Claude Code on the Linux machine that will manage your router (for another MCP client, see
[`docs/SETUP-CLIENTS.md`](docs/SETUP-CLIENTS.md)):

```text
Install Newton from https://github.com/kevwillow/newton-senior-engineer and follow SETUP.md there.
```

That's it. The agent reads [`SETUP.md`](SETUP.md) and does the rest. It checks the prerequisites, installs the
release you're shown and verifies it, and hands you **one** command to run with `sudo` yourself, so your password
never passes through the AI. That command creates a separate `newton` account that holds the router keys. Then the
agent helps you add your router: you pick your approval passphrase there, and you can scan a QR code into an
authenticator app to approve with 6-digit codes instead. Last, it runs a read-only checkup.

Prerequisites: Linux with `sudo`, `git`, an SSH client and Python 3 with `venv` (Debian/Ubuntu:
`sudo apt install python3-venv`). Prefer to do it by hand? See [Manual install](docs/INSTALL.md).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OpenWrt 25.12](https://img.shields.io/badge/OpenWrt-25.12-00B5E2)](#supported-devices)
[![Status: 1.1.2](https://img.shields.io/badge/Status-1.1.2-2f9a54)](#status)

## What it looks like

```text
You:     Put my smart-home stuff on its own network so it can't see my laptops.

Newton:  I read router1. Today everything shares one network (192.168.1.0/24, 23 devices).
         Plan: a new IoT network on VLAN 20 (192.168.20.0/24) with its own Wi-Fi "Home-IoT",
         internet allowed, your main network blocked.
         What could break: devices you move will need to rejoin the new Wi-Fi.
         Undo: automatic in 120 s unless the checks pass.
         Here is the exact change (14 lines) ... Shall I go ahead?

You:     yes

         ┌─ NEWTON ── MEDIUM CHANGE ── router1 ── expires 14:32 ──────────────┐
         │ Adds network iot (VLAN 20), Wi-Fi "Home-IoT", zone iot → wan only │
         │ Passphrase: (typed here; shown as you type it)        [Approve]   │
         └───────────────────────────────────────────────────────────────────┘

Newton:  NEWTON RESULT: CONFIRMED  router1  "IoT network on VLAN 20"
         Checked from a test client: IoT gets an address and internet ✓,
         IoT cannot reach 192.168.1.20 (your NAS) ✓. Receipt saved.
```

## What you can ask

- "Check my router and tell me what to fix." (a read-only checkup: listening services, port forwards, UPnP, Wi-Fi settings, connected devices)
- "Draw my network." (a map of your WAN links, VLANs, Wi-Fi and firewall zones, drawn only from what Newton read)
- "Give the printer a fixed address." / "Forward port 25565 to my game server."
- "Set up a guest Wi-Fi that can only reach the internet."
- "Turn off UPnP and show me what is open to the internet."
- "Fail over to my backup internet when the main line drops."
- "Harden this router." (three tested levels: Standard, Hardened, Lockdown)
- "Undo yesterday's change."

Questions like "why is the Wi-Fi slow?" stay read-only. Newton never changes anything without a plan you approved.

## Features

Everything Newton does, in one list. ✓ = shipping in 1.1.2.

**Changes that undo themselves**
- ✓ Plan → your approval (or your scoped grant; a lab router skips it) → apply → verify → keep, for every change. Nothing is written outside this flow.
- ✓ Apply-with-automatic-rollback over rpcd, with the timer on the router. In the **installed** mode the change is confirmed only after three consecutive passing rounds; in the **no-install** mode it is confirmed only when every mandatory check passes and the router's values read back as the staged ones, and the undo is OpenWrt's own rpcd timer (in the router's RAM).
- ✓ The undo timer is armed **on the router** before anything changes (60–600 s; 90 s default; 120 s or more is advised for Wi-Fi).
- ✓ A reboot-safe guard (installed mode only): a router that reboots in the middle of a change comes back with the old config.
- ✓ Verification over **new** connections, never from the session that made the change. In the installed mode: three passing rounds in a row. In the no-install mode: every mandatory check passes and the values read back as staged.
- ✓ Every verify round also checks that services still run and haven't restarted, and that the firewall config is valid.
- ✓ After an undo, every config file is compared with its state before the change. Any difference is raised as an ALERT.
- ✓ The staged firewall config is checked before you approve. Newton refuses to start if the current firewall config is already broken.
- ✓ Checks of the AI's claims: the AI writes down what should be true afterwards, and Newton checks those claims after the apply. A false claim triggers the undo.
- ✓ Live checks for each hardening setting a change touches, so a setting the router silently ignores is never kept.
- ✓ Checks from a client's point of view: DNS, DHCP and internet work, and anything meant to be blocked **is** blocked. A check that can't run is reported as "not tested", never as passed.
- ✓ Undo after confirm ("undo yesterday's change"), as a new approved change that notices anything edited since.
- ✓ A backup before every change, a backup tool, and a tested restore drill.
- ✓ A receipt for every change: what changed, who approved it, what was checked, and how to undo it. Plus an off-device copy of the backup.
- ✓ An audit log with the masked diff and who approved it.

**Approvals you control**
- ✓ An approval dialog in Claude Code, asking for your passphrase or an authenticator code (TOTP).
- ✓ `newton-approve` in a terminal, as the fallback for any client without dialogs.
- ✓ Changes rated LOW, MEDIUM or HIGH. HIGH (management access, internet exposure, options that run commands) needs a second typed confirmation every time.
- ✓ A one-time warning per device, accepted by typing the device's name.
- ✓ Scoped grants: "allow these kinds of change on this router until 6 pm". Never covers HIGH changes.
- ✓ A loud result after every change: `NEWTON RESULT: CONFIRMED / ROLLED BACK / UNKNOWN / REFUSED`.
- ✓ The dialog stops waiting after about three minutes (180 s) and tells you how to approve from a terminal.
- ✓ A reminder to clear your screen after typing a passphrase.
- ✓ Approval tokens are single-use and expire. Each one is bound to the exact change and the router's current config. On an installed OpenWrt router the router program checks it again; in the no-install mode and on VyOS, RouterOS and Junos only the Newton host checks it.
- ✓ The leash: changes to Newton's own access, the management network, internet exposure, or options that run commands always need approval.
- ✓ A lab mode for test routers you mark as lab-only.

**Security**
- ✓ The router keys belong to a separate `newton` account. The AI's user can't read them, and `newton-doctor` checks this.
- ✓ An MCP server with seventeen tools (`newton_list_devices`, `newton_read`, `newton_backup`, `newton_plan_change`, `newton_plan_undo`, `newton_apply_change`, `newton_change_status`, `newton_abort_change`, `newton_grant_off`, `newton_list_tiers`, `newton_plan_tier`, `newton_guided_recommend`, `newton_guided_audit`, `newton_plan_scan`, `newton_run_scan`, `newton_list_getters` and `newton_get_state`) and no tool that runs arbitrary commands, reboots, upgrades or installs packages. The last two are experimental read-only reads of non-OpenWrt devices by fixed getter id (never command text).
- ✓ A hard blocklist (factory reset, flash writes, bootloader, firewall flush and more) and an ask-first list.
- ✓ Wi-Fi keys and passwords in fields and values masked before they reach the AI. A secret written out as prose is not detected.
- ✓ Device text (hostnames, Wi-Fi names, logs, scan results) marked as untrusted data, with prompt-injection tests.
- ✓ A small on-router program with a closed command grammar that refuses anything not in it.
- ✓ A verified install: the installer asks you to type the full commit id of the release, and stops if it does not match.
- ✓ An optional question about Claude Code's managed settings (`allowManagedHooksOnly`): the default is no, and setting it means only hooks from the system settings run, so no agent hook can answer the approval dialog for you.

**Easy to use**
- ✓ One-line setup: paste the repo link into your coding agent.
- ✓ Network-engineer mode. Ask in plain words and Newton reads the router first, explains what it will change and what could break, and does one change at a time. Typing `/newton` or `/network-engineer` also starts it.
- ✓ Consequences first: "guests get internet and can't reach your NAS", with the config lines underneath.
- ✓ A smaller option offered next to a risky request, such as VPN-only access instead of a public port forward.
- ✓ Questions stay read-only. "Why is the Wi-Fi slow?" never changes anything.
- ✓ Router setup helpers: `newton-router-setup` (install, approval key, add key, upgrade, check, uninstall), `newton-enrol` (authenticator app, passphrase rotation, easy grant) and `newton-doctor`.
- ✓ A no-install mode for OpenWrt (`newton-router-setup DEVICE no-install`): nothing of Newton on the router but one limited web-interface user. Newton applies DHCP reservations and DNS entries itself under OpenWrt's own undo timer; every other change comes to you as a script you approve and run.

**Hardening**
- ✓ Three tested levels, Standard, Hardened and Lockdown, built from 47 researched controls covering management access, firewall, zones, DNS, DHCP, NTP, Wi-Fi, services, updates, logging and IPv6.
- ✓ Each level applied in ordered batches, with a reboot-survival test and an undo test.

**Checkup and scans**
- ✓ A guided interview (fourteen plain questions) that maps your answers to a hardening level and extras.
- ✓ A read-only audit: listening services, running services, port forwards, UPnP, Wi-Fi settings, connected devices.
- ✓ Recommendations, each with a reason and the exact change.
- ✓ nmap scans from inside your network and from outside it, only after you consent each time.
- ✓ A Wi-Fi scan with the router's own radio (channel crowding, look-alike networks), with consent, kept as summaries.
- ✓ A speed, latency, bufferbloat and Wi-Fi performance test that changes nothing on the router.

**Everyday changes, each a tested scenario**
- ✓ Fixed addresses (DHCP reservations), port forwards (add, change, remove), local DNS records, DNS upstreams, firewall allow and block rules, VLANs and zones, Wi-Fi settings, diagnostics.
- ✓ Wi-Fi proven on a real radio: WPA3 with management-frame protection, WPA2/WPA3 mixed, hidden networks, client isolation, WPS off.
- ✓ Dual-WAN failover and failback, run by a health check on the router (failover measured at 13 s, failback at 3 s in one lab run; the log of that run is not kept in this repository), including a second WAN on a VLAN.

**Network maps**
- ✓ "Draw my network": physical, VLAN, and firewall-zone diagrams drawn only from what Newton read. Anything guessed is marked "inferred".

**Other platforms**
- ✓ **Experimental:** changes with undo on VyOS, MikroTik RouterOS and Juniper Junos, each using the vendor's own undo method. Tested only on virtual images in the lab, never on real hardware.
- ✓ **Highly experimental:** read-only reads of RouterOS, VyOS, Junos, Arista EOS and Cisco IOS XE. Mostly untested on real devices; they never change anything. FortiOS has a profile but no read enabled yet.
- ✓ **Experimental:** a serial console tool for recovery when SSH is gone (probe, login, run, push; refuses the bootloader). Covered by unit tests and an OpenWrt console scenario in the lab. No run on a RouterOS, VyOS or Debian console is recorded in this repository.
- ✓ **Experimental:** a Linux host timed-undo recipe in the skill, verified on ifupdown2, netplan and NetworkManager. Full Linux support is planned for 1.3.

**Proven, not claimed**
- ✓ A virtual lab: a virtual OpenWrt router, two virtual ISPs and test clients, reset to a snapshot for every scenario.
- ✓ 96 scenarios in [`lab/scenarios`](lab/scenarios) for the virtual router, and a separate real-router suite in [`lab/scenarios-pulsar`](lab/scenarios-pulsar) (Wi-Fi included, through a USB adapter on the test client); its README lists which scenarios are ported.
- ✓ A lab isolation check: lab routers never leak DHCP or router adverts onto your home network.
- ✓ A support table generated from test results, with each device's undo method and what is untested.
- ✓ Works with Claude Code, Codex, OpenCode, Claude Desktop and any MCP client.
- ✓ On-demand reference docs for OpenWrt, nftables and networking concepts.

## How a change works

```text
 PLAN               APPROVE              APPLY                VERIFY               KEEP
 ────               ───────              ─────                ──────               ────
 read the router    you see the diff     the undo timer is    new connections      saved, with a
 back it up         in plain words,      armed ON THE ROUTER  check management,    receipt and an
 stage the change   say yes, then        before anything      services, and your   off-device backup
 check the staged   approve in the       changes              client-side checks
 firewall config    Newton dialog
                                         any failed check, or no answer in time → the router undoes it by itself
```

The undo timer lives on the router, so it still fires if the AI, your laptop or the connection dies mid-change. A
reboot inside the window comes back with the old config too.

That is the **installed** mode. In the **no-install** mode the changes do not go over SSH: they go over the router's own
web API, over HTTPS pinned by the certificate, the undo is OpenWrt's own rpcd timer (which lives in the router's RAM),
and a change is confirmed only when every mandatory check passes and the router's values read back as the staged ones.

The wrapper takes **probe lists**, not a free-form shell check: lists of 19 fixed types, sealed on the router at plan time. A manifest id is expanded by the host into probe lists before staging, so the router never sees an id. If the affected path cannot be tested from the router or the agent host, Newton does not auto-confirm: you test from a client and use `abort` before the window closes.

### Approvals

- On the default prod profile every change needs **your** approval, or a scoped grant you gave. A router you set to lab
  applies changes without asking, except the ones Newton always asks about. The AI cannot approve for you: the dialog
  asks for your passphrase or an authenticator code, which the model is not given. A passphrase does pass through the
  Claude Code process, can reach its debug log, and an installed hook could read it; an authenticator code (installed mode only) keeps the reusable passphrase out of them, but the dialog is not confidential and a code that is still valid could be used by whoever sees it.
  See Known limits in [`SECURITY.md`](SECURITY.md).
- Changes are rated LOW, MEDIUM or HIGH. HIGH changes (management access, anything exposed to the internet,
  options that run commands) need a second typed confirmation every time.
- **Scoped grants** make routine work quick: "allow DHCP reservations and DNS changes on router1 until 6 pm". Inside
  a grant you just see the diff and the result; anything outside it gets the full dialog.
- No dialog in your client, or you walked away? After about three minutes (180 s) Newton stops waiting and tells you how to
  approve from your terminal with `newton-approve`.

## What it will never do

- Write router config without the undo timer armed first.
- **Never confirm a change from the session that applied it.** In the **installed** mode, verification runs over new SSH connections with connection sharing disabled. In the **no-install** mode it runs over the router's own web API, over HTTPS pinned by the certificate, and the change is confirmed only when every mandatory check passes and the router's values read back as the staged ones.
- Give the AI your router credentials. They belong to the separate `newton` account.
- Let the AI approve its own plan, or loosen its own limits.
- Run factory resets, raw flash writes, bootloader changes or a firewall flush. These are on a hard blocklist.
- Treat text from your devices (hostnames, Wi-Fi names, logs) as instructions. It is marked as untrusted data.
- Show your Wi-Fi keys or passwords to the AI. Keys and passwords in fields and values are masked; a secret written out
  as prose is not detected.

## Supported devices

"Tested" means the same seven scenarios pass: a normal change, a management lockout that undoes itself, a firewall
lockout that undoes itself, an injection attempt rejected, bad syntax rejected, a service still reachable after the
change, and an uplink failure that undoes itself.

| Platform | Tested on | Undo method | Full features |
|---|---|---|---|
| OpenWrt 25.12 | a real Asus RT-AX57M and a virtual router | timer on the router + reboot-safe guard | changes, hardening levels, checkup, scans, maps |
| OpenWrt 25.12, no-install mode | the real Asus RT-AX57M | OpenWrt's own `uci apply` rollback timer (no reboot-safe guard) | DHCP reservations and DNS entries; other changes as owner scripts |
| VyOS (rolling), experimental | virtual image, in the lab | `commit-confirm`, reload mode | changes |
| MikroTik RouterOS 7, experimental | CHR virtual image, in the lab | scheduled restore (undo is a reboot) | changes |
| Juniper Junos, experimental | vJunos virtual image, in the lab | `commit confirmed` | changes |

OpenWrt is the supported platform. The other three are experimental: they pass the seven scenarios on virtual
images only, so try them on a device you can reach by console before you trust them on one you can't.

The full table, with versions and what is not tested, is generated from the test results:
[`docs/SUPPORT.md`](docs/SUPPORT.md). Linux hosts, firmware upgrades and more vendors are coming in 1.x
([roadmap](docs/ROADMAP.md)).

## Network maps

Ask "draw my network" and Newton maps what it can actually see: WAN links, VLANs and switch ports, Wi-Fi networks,
firewall zones, and anything open to the internet. Everything on the map was read from your router. Anything
guessed is drawn dashed and labelled "inferred". [See an example map](docs/assets/network-map-example.png).

## For reviewers and testers

You don't need real hardware to try Newton. The `lab/` directory builds a virtual OpenWrt router, two virtual ISPs
and a test client on Proxmox, and runs the scenarios against them. [`docs/TESTING-METHOD.md`](docs/TESTING-METHOD.md)
explains the method. [`docs/TESTING-FOR-REVIEWERS.md`](docs/TESTING-FOR-REVIEWERS.md) lists what to try first, and
the things we most want broken.

Test suites at this release:

| Suite | Path | Passing |
|---|---|---|
| MCP server | `mcp/tests/` | 6,640 (1 skipped) |
| Router program | `device/openwrt/newton-router/tests/` | 3,305 |
| Guard | `device/openwrt/newton-guard/tests/` | 183 |
| Protocol | `tests/protocol/` | 2,769 (4 skipped) |
| Lab scenarios | `lab/tests/` + live runs | 1,261 (2 skipped) |
| Profiles | `tests/profiles/` | 112 |
| Serial console | `tests/serial/` | 43 |

## Repository layout

```
README.md                 this file
SKILL.md                  the agent skill
SETUP.md                  what the coding agent follows to install Newton
commands/                 /network-engineer slash-command files for Claude Code and OpenCode
CHANGELOG.md              what shipped in each version
docs/                     install guide, roadmap, testing method, design package
lab/                      the lab runner, its scenarios and the example lab files
profiles/openwrt/         standard, hardened and lockdown profiles and their manifest
device/openwrt/           on-router programs: newton-router and newton-guard
mcp/newton_mcp/           the newton-mcp server (seventeen tools)
scripts/                  the change wrapper, the installer and the setup, doctor and scan helpers
tests/                    protocol, profile and serial tests
references/               on-demand OpenWrt, nftables and networking-concepts docs (own licenses)
```

## Security model

The AI is treated as an untrusted planner, and deterministic code decides. The router keys belong to a separate OS
account. An approval is a single-use token bound to the exact change and the router's current config, and it
expires. On an installed OpenWrt router the router program checks it a second time on the device; in the no-install mode and on VyOS, RouterOS and Junos only the Newton host checks it. The full threat model is in
[`docs/design/04-SECURITY-AND-SAFETY-MODEL.md`](docs/design/04-SECURITY-AND-SAFETY-MODEL.md). Found a hole?
See [`SECURITY.md`](SECURITY.md).

## Status

**1.0** covers OpenWrt (plus experimental VyOS, MikroTik and Junos), the one-line setup, in-client approvals, undo
after confirm, client-side checks and receipts. **1.1** adds a no-install mode for OpenWrt: Newton puts nothing on
the router but one limited web-interface user, applies DHCP reservations and DNS entries under OpenWrt's own undo
timer, and hands every other change to you as a script you approve and run. Next:

- **1.2:** network promises (rules like "the work laptop reaches the printer", re-checked on every change),
  reviewed recipes for common jobs, a blast-radius view, a generated network-map page.
- **1.3:** Linux hosts: network config, the local firewall and a hardening level.
- **1.4:** OpenWrt firmware upgrades.
- **1.5:** site files and rollouts for many devices.

## Works with

Built and tested with **Claude Code**. Any MCP client can use the server (Codex, OpenCode, Claude Desktop), and
[`docs/SETUP-CLIENTS.md`](docs/SETUP-CLIENTS.md) shows how. Clients without approval dialogs use `newton-approve` in
a terminal.

## How this got built

The code was written by AI models under a review-and-prove discipline. Every change comes with a test. A different
model reviews the work, the tests are re-run, and behaviour is proven in a lab rather than claimed.

## License

Newton's code and `SKILL.md` are [MIT](LICENSE). The reference docs under `references/` keep their own licences
(OpenWrt wiki: CC BY-SA 4.0; nftables wiki: GFDL 1.3+; networking concepts: CC BY 4.0). See
[`NOTICE.md`](NOTICE.md) and [`LICENSES/`](LICENSES/).
