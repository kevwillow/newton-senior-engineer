# EOS profile notes (UNVERIFIED)

## Status
Experimental read-only. Tier T0-exp on the capability registry.
Every shipped getter is `verified = "unverified"`. `os_range` stays unset
until a lab run records a real lab receipt on the EOS lab (cEOS-lab;
none exist here yet). `device_role_enforced` is false for every EOS
device until a lab-verified ledger entry exists; until then the only
proven wall against writes is Newton's getter allowlist.

## Getters
- `version` — `show version` — enabled.
- `interfaces` — `show ip interface brief` — enabled.
- `routes` — `show ip route` — enabled.
- `running_config` — `show running-config sanitized` — **disabled** —
  masking is a doc-claim until lab proves the role's `show`
  restrictions plus the `sanitized` form hide every secret form
  (SNMP community strings, RADIUS/TACACS shared secrets, BGP MD5). Newton keeps it
  disabled (still `secret_bearing = true`) until a lab capture confirms it.

No other getter ids ship in this release (no firewall, nat,
mgmt_services, admins, logging, ntp, vpn).

## Unknown until lab
- Whether exec-mode commands page on the no-PTY exec channel. `terminal
  length 0` and `| json` are unconfirmed and are deliberately omitted (no
  pipe suffix, no pre-command); a lab capture measures and decides.
- Exact output shapes and exact error strings: the `error_markers`
  list is a best-guess subset; lab capture sharpens it.
- Whether the role below truly blocks `>`, `| tee`, and `| append`
  redirections even when only `show` commands are permitted.
- Whether `show running-config sanitized` strips SNMP community
  strings, RADIUS/TACACS keys and BGP MD5 at every level; doc-claim
  until a lab capture confirms it.
- Whether `show tech-support` (explicitly denied below) is reachable
  via indirect paths in any release.

## Setup recipe (UNVERIFIED)
Only devices the maintainer owns (design decision 6).

1. The built-in `network-operator` role is **not** read-only: it permits
   `reload`, `write`, `copy`, `delete`, `clear`, and similar at exec
   level. It must not be used as the Newton role (doc-claim on what the
   built-in role permits; unconfirmed on this lab release).
2. Create a custom role whose rules permit only `show` commands in
   exec mode. The role must explicitly deny (at minimum, on every
   action class the release supports): `bash`, `|` redirect, `| tee`,
   `| append`, `>`, `configure`, `copy`, `write`, `reload`, `delete`,
   `clear`, `enable`, and `show tech-support`. Exact wording and rule
   precedence are release-specific (unconfirmed).
3. Add a user with that role and an SSH key used only by Newton
   (`<key-file>`).
4. Capture the host fingerprint from the console and store it in the
   per-device `known_hosts` (`StrictHostKeyChecking=yes`).
5. Inventory entry sets `platform = "eos"`, `host`, `user`, `key_file`,
   `known_hosts`, and `experimental_readonly = true`. The role is not
   an inventory field; it is the device-side check that the user is
   bound to the role above. `device_role_enforced` is a result field
   Newton sets, and it is false for every EOS device until
   a lab capture records otherwise.

## Sources
Every claim is from Arista EOS documentation (root URL as in the getter
`source`) and is UNVERIFIED. Per-claim deep links are added
when the lab capture confirms them.
