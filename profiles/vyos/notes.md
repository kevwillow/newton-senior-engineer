# VyOS profile notes

## Status
Experimental read-only. Tier T0-exp on the capability registry.
The enabled getters are lab-observed on VyOS 2026.10.01-0035-rolling
(2026-10-18). The seven enabled rows carry that receipt and
`os_range = "2026.10.01-0035-rolling"`. This is a T0 read-only observation,
not write certification. VyOS is **lab only**: the inventory entry for any
VyOS device must set `lab = true` before Newton touches it. There is no
read-only operator role in VyOS, so `device_role_enforced` stays `false`
and the wall against writes is Newton's getter allowlist and SSH key use,
not the device.

Verification scope: `ntp` (no servers configured) and `vpn` (no IPsec)
were seen only in their empty state. The `firewall_policy` and `nat`
recordings used rules planted, unsaved, on the lab VM and removed by a
snapshot rollback. Of the error markers, only `Invalid command` was observed.

## Getters
- `version` — `show version` — enabled.
- `interfaces` — `show interfaces` — enabled.
- `routes` — `show ip route` — enabled.
- `firewall_policy` — `show firewall` — enabled.
- `nat` — `show nat source rules` — enabled.
- `ntp` — `show ntp` — enabled.
- `vpn` — `show vpn ipsec sa` — enabled.
- `running_config` — `show configuration commands` — **disabled** —
  decision 4: no config getter for VyOS in v1. The lab output carried the
  login password hash and the plaintext-password line; Newton's redaction
  masked both, but the getter stays off.

The `mgmt_services`, `admins` and `logging` getters are not in the table.
Operational-mode read views for those would either return the configuration
(secret-bearing) or the log contents (unbounded, attacker-controlled).
Decision 10 keeps them off this list for now.

## Lab observations
- The SSH exec channel runs commands in vbash, which has no op mode:
  `show version` failed with `Invalid command: [show]`, exit 127. Newton's
  transport therefore sends every VyOS command through the fixed path
  `/opt/vyatta/bin/vyatta-op-cmd-wrapper`, added after the `show` grammar
  check. Through SSH a bad command exits 1 with the text on stderr; on a
  console it exited 0, so the `Invalid command` marker is what classifies it.
- No paging on a no-PTY exec channel: a 222-line `show configuration
  commands` printed in full (all 222 lines) with no ESC byte.
- An empty table prints a sentence (`NAT is not configured`, `IPsec not
  initialized`), so it is `ok` output, not `empty`.

## Setup recipe — lab-observed on VyOS rolling (2026-10-18)
Lab only. No production VyOS box is in scope.

1. On the lab VyOS console, add a login user with a key used only by
   Newton, from a vbash script that sources
   `/opt/vyatta/etc/functions/script-template`, then runs `configure`,
   `set system login user newton authentication public-keys newton type
   ssh-ed25519`, `... public-keys newton key <base64>`, `commit`, `save`.
   VyOS puts every login user in the sudo and adm groups: this user can
   configure the device, so the only wall is the getter allowlist. The lab
   environment is the only thing keeping a misfire from mutating it.
2. The key must not appear in any other device's `key_file` column.
3. Capture the host key out of band from the console
   (`cat /etc/ssh/ssh_host_ed25519_key.pub`) and store it in the
   per-device `known_hosts` (`StrictHostKeyChecking=yes`).
4. Inventory entry sets `platform = "vyos"`, `host`, `user`, `key_file`
   (the key in step 1), `known_hosts` (the per-device file from step 3),
   `experimental_readonly = true`, and `lab = true`. The inventory
   holds no per-device role field; `device_role_enforced` is a result
   field Newton sets, and it is always false for VyOS.

## Sources
Getter `source` values retain the VyOS documentation root. The operational
claims above come from the recorded lab-vyos run dated 2026-10-18.
