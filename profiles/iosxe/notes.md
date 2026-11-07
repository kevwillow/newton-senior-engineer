# IOS XE profile notes (UNVERIFIED)

## Status
Experimental read-only. Tier T0-exp on the capability registry.
Every shipped getter is `verified = "unverified"`. `os_range` stays unset
until a lab run records a real lab receipt on an IOS XE device. The
IOS XE lab is DevNet sandbox (terms unread) or a paid CML node; CML-Free
ships IOL, not IOS XE, so it cannot exercise these getters here.
`device_role_enforced` is `false` for every IOS XE device until a
lab-verified ledger entry exists; until then the only proven wall against
writes is Newton's getter allowlist (doc-claim on how IOS XE
authorization works in current releases).

## Getters
- `version` -- `show version` -- enabled.
- `interfaces` -- `show ip interface brief` -- enabled.
- `routes` -- `show ip route` -- enabled.
- `running_config` -- `show running-config` -- **disabled** -- IOS XE
  has no device-side masking form analogous to EOS `sanitized` or Junos
  class. `show running-config` prints `username ... secret 5 ...` hashes
  and `key chain` plaintext keys inline, so the row stays disabled and
  `secret_bearing = true` until a lab proves a usable mask (design 4;
  doc-claim on what `show running-config` prints).

No other getter ids ship in this release (no firewall, nat, mgmt_services,
admins, logging, ntp, vpn). No `admins` row in v1; user tables never go
to the model.

## Unknown until lab
- Whether exec output pages on the no-PTY exec channel. `terminal length
  0` is a doc-claim and is deliberately omitted (no pipe suffix, no
  pre-command); a lab capture measures and decides.
- Whether IOS XE accepts an exec channel at all from Newton's argv list
  (`RequestTTY=no`, `BatchMode=yes`); doc-claim until the lab proves it.
- Exact output shapes and exact error strings: the `error_markers` list
  is a best-guess subset (doc-claim on the prefix strings; unconfirmed
  on whether newer releases add new shapes).
- Whether the parser view's `commands parser-mode` parses `show version`,
  `show ip interface brief`, `show ip route` as Newton ships them
  (doc-claim on parser view syntax).
- Whether abbreviating with `sh ver` / `sh ip ro` is also blocked; the
  device-side denial of abbreviate forms is unconfirmed.

## Setup recipe (UNVERIFIED)
Only devices the maintainer owns (design decision 6).

1. Enable `aaa new-model` so per-command authorization is possible
   (doc-claim on the prerequisite).
2. Configure `aaa authorization exec` and per-command authorization
   against the local username database (doc-claim; exact CLI varies
   by release).
3. Create a `parser view <view-name>`; set its `secret <view-secret>`
   from the console, never stored by Newton. The view's `commands
   parser-mode` allow-list must contain only `show version`,
   `show ip interface brief`, `show ip route` and nothing that reaches
   `configure`, `copy`, `write`, `reload`, `debug`, `clear`, `test`,
   `request`, `more`, `show running-config`, `show tech-support`, or
   `show logging` (doc-claim; exact wording release-specific, unconfirmed).
4. Add `username <newton-user> view <view-name> ...` with an SSH public
   key used only by Newton (`<key-file>`). No `enable` is granted; no
   `enable secret` is configured.
5. Capture the host fingerprint from the console and store it in the
   per-device `known_hosts` (`StrictHostKeyChecking=yes`). The first
   SSH probe must not accept the fingerprint -- that is the MITM path.
6. Inventory entry sets `platform = "iosxe"`, `host`, `user`, `key_file`,
   `known_hosts`, `experimental_readonly = true`. `device_role_enforced`
   is a Newton-set result field, false for every IOS XE device until
   a lab capture records otherwise.

## Sources
Every claim is from Cisco IOS XE documentation (root URL as in the
getter `source`) and is UNVERIFIED. Per-claim deep links are added when the lab capture confirms them.
