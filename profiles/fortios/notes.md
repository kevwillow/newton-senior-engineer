# FortiOS profile notes (UNVERIFIED)

## Status
Experimental read-only. Tier T0-exp on the capability registry.
Every shipped getter is `verified = "unverified"` **and disabled**.
`os_range` stays unset until a lab run records a real lab receipt on
a FortiGate-VM. Neither an IOS XE lab nor a FortiGate-VM exists in the
lab yet. `device_role_enforced` is `false` for every FortiOS device
until a lab-verified ledger entry exists. Because every getter ships
disabled, `newton_get_state` refuses every FortiOS getter today
(design 2.6 and 10.1/10.6); until a lab proves the accprofile `read`
truly blocks `execute` over a no-PTY exec channel, no FortiOS getter is
exercised.

## Getters
- `version` -- `get system status` -- disabled.
- `interfaces` -- `get system interface physical` -- disabled.
- `routes` -- `get router info routing-table all` -- disabled.
- `firewall_policy` -- `show firewall policy` -- disabled.
- `nat` -- `show firewall vip` -- disabled.
- `ntp` -- `show system ntp` -- disabled.
- `logging` -- `show log syslogd setting` -- disabled (the syslog
  setting, not log contents; design decision 10).
- `vpn` -- `show vpn ipsec phase1-interface` -- disabled.
- `running_config` -- `show full-configuration` -- **disabled** --
  FortiOS `show full-configuration` prints `set <field> ENC ...`
  ciphertext (still secret material) and may print other secret forms
  (unconfirmed); the row stays disabled and `secret_bearing = true` until a
  lab proves a safe form (design 4; doc-claim on what the release
  prints).

All nine getters are disabled because (a) accprofile `read` is not
proven to block `execute`, and (b) whether FortiOS accepts an exec
channel at all from Newton's argv list is unconfirmed (doc-claim on the
release behaviour; unconfirmed here). No `admins` row in v1; user
tables never go to the model.

## Unknown until lab
- Whether exec output pages on the no-PTY exec channel. `config system
  console` with `set output standard` is a config write and is never
  sent by Newton; the un-paged behaviour is unconfirmed. A lab capture
  measures and decides.
- Whether FortiOS accepts an exec channel at all from Newton's argv list
  (`RequestTTY=no`, `BatchMode=yes`); doc-claim until the lab proves it.
- Exact output shapes and exact error strings: the `error_markers`
  patterns are a best-guess subset (doc-claim on the prefix strings;
  unconfirmed on whether newer releases add new shapes).
- Whether the accprofile matches abbreviations such as `sh fir pol`
  (unconfirmed).
- Whether `system-diagnostics` must be disabled in the accprofile for
  the read profile to remain stable; unconfirmed.

## Setup recipe (UNVERIFIED)
Only devices the maintainer owns (design decision 6).

1. Create an access profile with every group set to `read` (or `none`).
   If the release offers a `system-diagnostics` group, set it to `none`
   (unconfirmed that the release offers this knob; doc-claim on what
   groups the release exposes).
2. Create an admin with that accprofile and `trusthost` limited to
   `<newton-host>` (doc-claim on the field name; exact field is
   release-specific, unconfirmed).
3. Add an SSH public key used only by Newton (`<key-file>`); no
   password-only auth.
4. No VDOM switch: `config vdom` and `config global` are writes or
   context switches and are never sent. Newton stays in the default
   VDOM the admin was created in.
5. Capture the host fingerprint from the console and store it in the
   per-device `known_hosts` (`StrictHostKeyChecking=yes`). The first
   SSH probe must not accept the fingerprint -- that is the MITM path.
6. Inventory entry sets `platform = "fortios"`, `host`, `user`, `key_file`,
   `known_hosts`, `experimental_readonly = true`. `device_role_enforced`
   is a Newton-set result field, false for every FortiOS device until
   a lab capture records otherwise.

## Sources
Every claim is from FortiOS documentation (root URL as in the getter
`source`) and is UNVERIFIED. Per-claim deep links are added
when the lab capture confirms them.
