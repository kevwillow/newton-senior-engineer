# Junos profile notes

## Status
Experimental read-only. Tier T0-exp on the capability registry.
The three enabled getters are lab-observed on vJunos 26.2R1.7 (2026-10-18,
Proxmox VM, user `newton-ro` in the built-in `read-only` class). Each
carries `verified = "lab:vjunos:26.2R1.7:2026-10-18"` and
`os_range = "26.2R1.7"`. This is a T0 read-only observation, not write
certification. `running_config` stays `verified = "unverified"` and
disabled. `device_role_enforced` stays `false` for every Junos device;
whether to change that is the maintainer's decision, not made here.

Verification scope: one device, one release, one login class. `version`,
`interfaces` and `routes` each ran once and matched their `expect` shape;
the recordings are in `mcp/tests/fixtures/vendors/junos/recorded/`
(MAC-derived and lab addresses substituted). `routes` was seen with two
routes per table only. One bad command (`show bogus`) was tried; its
body matched the Junos marker `(?m)^error: ` and also the global
`syntax error` marker; `unknown command` and
`is ambiguous` were not seen. The exit code of the bad command was not kept.
Abbreviated commands (`sh ver`) were not tried.

## Getters
- `version` — `show version` — enabled.
- `interfaces` — `show interfaces terse` — enabled.
- `routes` — `show route` — enabled.
- `running_config` — `show configuration` — **disabled**, still
  `secret_bearing = true`.

No other getter ids ship (no firewall, nat, mgmt_services, admins,
logging, ntp, vpn).

## Lab observations
- No paging on the no-PTY exec channel: the three getters printed in full
  with no pipe suffix and no pre-command. `set cli screen-length 0` and
  `| no-more` are still omitted.
- A bad command prints a blank line, then
  `error: syntax error, expecting <command>: bogus`, on stdout.
- Under `read-only`, `show configuration` was refused per stanza: the
  output began `## Last commit: ...` and each top-level stanza read
  `/* ACCESS-DENIED */` (`version /* ACCESS-DENIED */;`, `system {
  /* ACCESS-DENIED */ };`, and so on). No secrets were returned. This
  output still matches the `version *` expect shape, so if the getter were
  enabled it would classify as `ok` on a denied read. Until that is
  handled, `running_config` stays off. Whether `show configuration` masks
  secrets under a wider class is not observed.
- `show version` prints a `Junos: 26.2R1.7` line near the top, then the
  package list (about 70 lines).

## Setup recipe (lab-observed only where stated)
Only devices the maintainer owns (design decision 6).

1. Add a login user in a class with only `view` permissions. The lab used
   the built-in `read-only` class (observed). A custom class with
   `view` and `view-configuration` is a doc-claim and unconfirmed. The
   class must not be granted `secret`, `shell`, `maintenance`, `network`
   (allows ping, ssh, telnet, traceroute), `configure`, `control` or
   `all`.
2. Deny-commands for request, restart, clear, start shell, file, load,
   configure, set, delete, commit, rollback and test is a doc-claim,
   unconfirmed on a real device. Newton's getter grammar already excludes
   these verbs.
3. Give the user an SSH key used only by Newton (`<key-file>`).
4. Capture the host key from the console (`file show
   /etc/ssh/ssh_host_ed25519_key.pub`, observed) and store it in the
   per-device `known_hosts` (`StrictHostKeyChecking=yes`). Never accept
   the fingerprint on the first SSH probe.
5. Inventory entry sets `platform = "junos"`, `host`, `user`, `key_file`,
   `known_hosts` and `experimental_readonly = true`. `device_role_enforced`
   is a result field Newton sets; it is false for Junos.

## Sources
Getter `source` values retain the Junos documentation root. The
operational claims above come from the recorded vJunos run dated
2026-10-18; setup claims marked doc-claim are from documentation only.
