# Roadmap

Newton ships one 1.x release per platform group. In every release, "supported" means the same seven scenarios pass
(a normal change, a management lockout that undoes itself, a firewall lockout that undoes itself, an injection attempt
rejected, bad syntax rejected, a service still reachable after the change, and an uplink failure that undoes itself),
and the support table ([`SUPPORT.md`](SUPPORT.md)) names the undo method and what is not tested.

## Released

| Release | Ships |
|---|---|
| 1.0 | OpenWrt 25.12 (a virtual router and a real Asus RT-AX57M), with experimental VyOS, MikroTik RouterOS and Junos changes tested on virtual images; the one-line setup, in-client approvals, undo after confirm, client-side checks and change receipts |
| 1.1 | The no-install mode for OpenWrt: Newton puts nothing on the router but one limited web-interface user, talks to the router's own web API over pinned HTTPS, applies only DHCP reservations and DNS entries by itself under OpenWrt's own undo timer, and hands every other change to the owner as a script; the installed mode stays one command away |
| 1.4.0 | The Active Directory audit (read-only, Windows Server AD and Samba AD) and Active Directory changes (each approved by the owner, with the undo armed on the domain controller until Newton confirms; once confirmed, Newton does not undo it (a known limit: if the PDC role moves while an earlier change of the same target is still armed on the old PDC, that domain controller's undo can write the earlier before-image over the new change): the owner plans the reverse change; an unlock has no undo and is written at once); `newton_confirm_change`, which keeps a change applied with hold; and all fixes since 1.1.3. Not built yet: a reviewed script for the Active Directory changes Newton will not make (deletes, password resets, krbtgt, trusts, privileged groups), and Group Policy edits |
| 1.4.1 | Fixes from the fourth review round, no new tools: the firewall restart that a rolled-back change on named nft objects now owes and says so, the no-install grant-off, bounded nmap results, the guard keeping quarantined config files, the upgrade of a restored or failed guard, the TOTP approval hint and the installed launcher forms in every hint, the Active Directory install-check refusals and status reasons, serial console and installer robustness. [`CHANGELOG.md`](CHANGELOG.md) lists them. |
| 1.4.2 | Two Active Directory fixes on Windows domain controllers, no new tools: the 1.3 audit setup and the 1.4 write setup no longer strip each other's read of the shared install folder, and the collector reports a search root the audit account may not read as access denied instead of an error |

## Planned

| Release | Ships |
|---|---|
| 1.2 | Network rules, partly shipped (the store, `newton-rules`, shipped in 1.1.3 and no change reads it yet; owner-written rules such as "the work laptop reaches the printer" or "IoT cannot reach the router admin" are to be re-checked from a client on every change to the router they belong to); reviewed recipes for common jobs (guest or IoT network, DHCP reservations, WireGuard, port forward, DNS, bufferbloat); the blast radius before approval (the Wi-Fi networks, VLANs and devices that depend on what a change touches); a recovery card before a risky change; a generated network map and read-only report pages written as local files |
| 1.5 | Active Directory build mode: a whole domain, from a fresh Windows Server through installation, hardening and setup, built from one plan the owner reviews and approves once, with a fresh yes before every stage that cannot be undone; opt-in only |
| 1.5.x | The protocol contract: the change protocol written down as one contract that every mode follows, each part named with its tests; a recovery line for each mode in the approval text; when the router's guard restores a change on its own, the running settings are made to match the restored files, and where Newton cannot show they match it says so plainly and prints the command that fixes it; a record on the router that the checks passed, which the confirm requires; recorded runs in which the controller is lost in the middle of a change |
| 1.6 | Hosts: Linux and Windows 11 PCs. Full environment builds (home, lab and dev machines), network configuration, the local firewall and a hardening level, and a gaming performance advisor for Windows 11 (Windows settings, drivers and installs, and curated, sourced in-game settings). Newton advises and writes a reviewed script by default; an opt-in mode lets it apply staged changes itself, behind a command blocklist, for labs where that friction is not worth it |
| 1.7 | A security engineer persona: reads Wazuh alerts, explains them and proposes fixes that go through the same approval and undo |
| 1.8 | More vendors, limited to OpenWrt, Asus and GL.iNet routers and to what the lab can test safely; FortiGate, Arista EOS, Cisco IOS XE and other vendors come later |
| 1.x | Passkey approvals: approve a change from this machine or from a phone with a passkey (unlocked with the device's fingerprint, face or PIN, or held on a security key) bound to that exact change, on its own small approval page, with its own threat model, including what an AI on the same machine could still do |
| Later | OpenWrt firmware upgrades (exact image, signed checksum, off-device backup, settings kept, verified over a fresh connection; no undo, so always high risk); site files and canary-first rollouts across many devices |
| Backlog | Parked at the end of the backlog: a read-only local dashboard, a generic policy engine, maintenance windows, orchestration across several systems, and a kit for third-party adapters |

Plans change; [`CHANGELOG.md`](../CHANGELOG.md) is the record of what shipped.
