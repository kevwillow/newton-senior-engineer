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
| 1.3 | Windows and an Active Directory audit: a Windows connection through a restricted PowerShell endpoint, Windows Firewall changes with an undo armed first, and a read-only security audit of Windows Server AD and Samba AD domains (privileged groups, Kerberos and password policy, risky account flags, delegation, LDAP signing and NTLM, stale accounts) |
| 1.4 | Active Directory changes: users, groups, OUs, Group Policy edits and the audit's hardening fixes, each with its undo armed first where one exists; a change that cannot be undone, such as a password reset, says so and is always high risk; a change is confirmed only when every domain controller shows it, and stays unconfirmed when one cannot be checked; no deletes at first |
| 1.5 | Linux hosts: network configuration, the local firewall and a hardening level, tested per network stack |
| 1.6 | More vendors: FortiGate through its REST API, then Arista EOS and Cisco IOS XE, each when its seven scenarios pass |
| 1.7 | A security engineer persona: reads Wazuh alerts, explains them and proposes fixes that go through the same approval and undo |
| 1.x | Passkey approvals: approve a change in the local dashboard, or from a phone, with a passkey (unlocked with the device's fingerprint, face or PIN, or held on a security key) bound to that exact change; designed after the read-only dashboard ships, with its own threat model, including what an AI on the same machine could still do |
| Later | OpenWrt firmware upgrades (exact image, signed checksum, off-device backup, settings kept, verified over a fresh connection; no undo, so always high risk); site files and canary-first rollouts across many devices, with maintenance windows |

Plans change; [`CHANGELOG.md`](../CHANGELOG.md) is the record of what shipped.
