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

## Planned

| Release | Ships |
|---|---|
| 1.2 | Network rules (owner-written rules such as "the work laptop reaches the printer" or "IoT cannot reach the router admin", re-checked from a client on every change to the router they belong to); reviewed recipes for common jobs (guest or IoT network, DHCP reservations, WireGuard, port forward, DNS, bufferbloat); the blast radius before approval (the Wi-Fi networks, VLANs and devices that depend on what a change touches); a recovery card before a risky change; a generated network map and read-only report pages written as local files; a read-only local dashboard |
| 1.3 | An Active Directory audit: a read-only security audit of Windows Server AD and Samba AD domains (privileged groups, Kerberos and password policy, risky account flags, delegation, LDAP signing and NTLM, stale accounts), through a key-only SSH login with a fixed forced command (`collector.ps1`) on Windows and a fixed helper on Samba; it changes nothing |
| 1.4 | Active Directory changes: Newton writes account flags, encryption types, disable and enable, membership of non-privileged groups, the machine account quota, new disabled users and moves between OUs, each approved by the owner, with the undo armed on the domain controller until Newton confirms; the controller checks the owner's approval itself; a change is confirmed only when every domain controller with a write entry in the inventory shows it, and aborted otherwise; once confirmed, Newton does not undo it: the owner plans the reverse change. An unlock has no undo and is written at once. Changes that cannot be cleanly undone (deletes, password resets, krbtgt, trusts, privileged groups) come as a reviewed script the owner runs; Group Policy edits follow in a second phase |
| 1.5 | Active Directory build mode: a whole domain, from a fresh Windows Server through installation, hardening and setup, built from one plan the owner reviews and approves once, with a fresh yes before every stage that cannot be undone; opt-in only |
| 1.6 | Hosts: Linux and Windows 11 PCs. Full environment builds (home, lab and dev machines), network configuration, the local firewall and a hardening level, and a gaming performance advisor for Windows 11 (Windows settings, drivers and installs, and curated, sourced in-game settings). Newton advises and writes a reviewed script by default; an opt-in mode lets it apply staged changes itself, behind a command blocklist, for labs where that friction is not worth it |
| 1.7 | More vendors: FortiGate through its REST API, then Arista EOS and Cisco IOS XE, each when its seven scenarios pass |
| 1.8 | A security engineer persona: reads Wazuh alerts, explains them and proposes fixes that go through the same approval and undo |
| 1.x | Passkey approvals: approve a change in the local dashboard, or from a phone, with a passkey (unlocked with the device's fingerprint, face or PIN, or held on a security key) bound to that exact change; designed after the read-only dashboard ships, with its own threat model, including what an AI on the same machine could still do |
| Later | OpenWrt firmware upgrades (exact image, signed checksum, off-device backup, settings kept, verified over a fresh connection; no undo, so always high risk); site files and canary-first rollouts across many devices, with maintenance windows |

Plans change; [`CHANGELOG.md`](../CHANGELOG.md) is the record of what shipped.
