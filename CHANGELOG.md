# Changelog

All notable changes to Newton. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). Before 1.0.0 any minor release may change behaviour.

This repository starts at 1.1.2. The earlier versions are listed below for history only; their tags are not in this
repository.

Two version numbers exist and are separate:
- the **Newton release** (this file, the git tag, `mcp/pyproject.toml`);
- the **router program** `newton-router` (its `hello` line, `version=`), bumped whenever that one file changes,
  because the lab snapshot pins its hash.

## [Unreleased]

### Added
- An Active Directory audit for Windows Server AD and Samba AD domains: `newton_ad_list_checks` and
  `newton_ad_audit`, 48 read-only checks (privileged groups, Kerberos and password policy, risky account flags,
  delegation, LDAP signing and NTLM, stale accounts). Newton reads through a key-only SSH login of an ordinary account
  that runs one fixed command (on Samba that command runs the read-only collector as root through sudo, with no
  arguments); `scripts/newton-ad-setup windows|samba` prints the script the owner runs on each domain controller. On an
  installed Newton, `docs/INSTALL.md` step 10 gives the commands for the keys, the pinned host key and the inventory
  entries. The audit changes nothing.
- Active Directory changes: `newton_ad_plan_change`, `newton_ad_apply_change`, `newton_ad_change_status` and
  `newton_ad_abort_change`, for account flags, encryption types, disable and enable, membership of non-privileged
  groups, the machine account quota, new users (created disabled), moves between OUs, and unlock. The undo is armed on
  the domain controller until Newton confirms; `newton_ad_apply_change` confirms or aborts before it returns, and when a
  DC does not catch up its result says what the undo restored and which attributes it left as conflicts.
  `newton_ad_abort_change` works only on a change still armed (an apply cut off before its confirm). Once confirmed,
  Newton does not undo it: the owner plans the reverse change. An unlock has no undo and is written at once. The owner approves each change in their own terminal with
  `sudo -u newton /usr/local/bin/newton-approve ad-change <plan_id>`; the
  domain controller checks that approval itself and arms its undo before it writes, and Newton confirms a change only
  when every domain controller with a write entry in the inventory shows it. Newton does not list the DCs of the
  directory, so a DC without a write entry is never read; each plan lists the DCs it will check and says so. `scripts/newton-ad-setup write windows|samba` sets up the `newton-ops`
  account, which is never in a privileged group and holds only the rights these changes need. The write helpers were
  tested live in the lab on Windows Server 2025 and Samba 4.22 domain controllers. The second-DC setup
  (--domain-device), the printed ad_domain_guid and changes on a domain with two domain controllers were tested live
  on a two-DC Windows Server 2025 domain and a two-DC Samba domain: both DCs of a domain hold the same approval key,
  every change is confirmed on both, and a withheld confirm rolls back on both. A move of the PDC role between domain
  controllers was not tested live.
- `SKILL.md` has an Active Directory section: the setup, the audit, the change flow and what Newton does not change.
- An installed Newton has a new launcher, `/usr/local/bin/newton-ad-setup`, with its own sudoers rule (no
  `NOPASSWD`, `timestamp_timeout=0`): `sudo -u newton /usr/local/bin/newton-ad-setup approval-key <device>` records
  the AD approval fingerprint in the newton user's state directory, where `newton-approve` reads it. It takes
  `approval-key` and one device name, nothing else. The `newton-approve` launcher takes `ad-change <plan_id>` as well
  as a lone plan id, and `newton-doctor` checks the new launcher like the others.

### Known limits
- Changes work only while the PDC emulator's own write entry is in the inventory and names the device that stands
  for the domain; if the PDC role moves to a controller without a write entry, every change is refused until the
  inventory follows it.
- Newton does not change privileged groups, delete objects, reset passwords, reset krbtgt, or change trusts,
  functional levels or Group Policy, and there is no owner-script tool for Active Directory yet.

## [1.1.3] - 2026-11-09

### Fixed
- Changes on OpenWrt 25.12.6 work again. Its rpcd keeps each session in a folder with a random name, so
  Newton could not find the session it stages a change in, and every apply stopped safely before writing. The change
  helper, the router program and the owner script now look the folder up, accept only a folder of the exact expected
  form, and destroy the session if the lookup fails. Tested end to end on a GL-MT3000 running vanilla OpenWrt 25.12.6.

### Added
- `scripts/newton-rules`, the owner's tool for the network rules file (`add`, `remove`, `list`). This is the first part
  of the 1.2 network rules: planning does not read the file yet, so a rule changes nothing in this release.

### Changed
- The router program is version 1.3.1.
- The public repository is renamed from `newton-network-engineer` to `newton-senior-engineer`, because Newton is
  growing past networks. GitHub redirects the old address; the clone commands, the security-report link and the
  install guide name the new one.
- The roadmap has a new release order: 1.3 Windows and an Active Directory audit, 1.4 Active Directory changes, 1.5
  Active Directory build mode, 1.6 Linux and Windows 11 hosts, 1.7 FortiGate and more vendors, 1.8 a security
  engineer persona, passkey approvals in 1.x; firmware upgrades and site files move to Later. The 1.2 plan renames "network promises" to "network rules" and plans to
  re-check them on every change to the router they belong to, not only on changes that touch them.

## [1.1.2] - 2026-11-06

### Changed
- The no-install setup, and every later admin step on a no-install router, now logs in with the router's root password by default, not the plain key. The plain key no longer has to be made or added to the router for the no-install mode, and the setup does not read it unless you pass `--admin plain-key` or `--plain-key`. If a router still holds a plain key from an older setup, the setup prints one INFO line saying so and how to remove it; the no-install setup never removes a key (`swap-key` and `uninstall` remove only Newton's own key lines).
- `SECURITY.md` names a contact email address next to GitHub private vulnerability reporting.

### Fixed
- The approval dialog for a change that offers a time-limited grant was never shown, because the SDK refused its form, so every such change fell back to approving in a terminal; it is shown again.
- A `check` whose router login failed left the router's host key saved, so the next run used it without showing the fingerprint to compare; a failed login now saves nothing.
- `newton-doctor --device NAME` on an installed router hid the setup tool's prompt for the router's root password,
  so the doctor seemed to hang; the prompt now shows on the terminal.

### Removed
- **The pre-1.0 key-label fallback.** `newton-router-setup` no longer keeps the old default key label for a router
  enrolled before 1.0: the default label is always `newton-agent`, and a label the owner types is used as typed.

## [1.1.1] - 2026-11-05

### Added
- The seven support-table shapes in the no-install mode (`lab/scenarios-pulsar-noinstall/`, driven by
  `lab/noinstall-shape.py` through the real Newton service and the real owner-run). First recorded run on the Asus
  RT-AX57M test router, 2026-11-02: a, d, e and f pass; b and c pass as refusals (a change that cuts off Newton's own
  access is refused when it is planned, so nothing is applied); **g fails**: Newton confirms an owner script that takes
  every uplink down, because nothing in the no-install read-back checks that the internet still works. Second recorded
  run, the same day, after the fixes below: all seven pass, g included (the change is not confirmed and the router puts
  it back).

### Changed
- `newton-router-setup check`: an empty dropbear `PasswordAuth` or `RootPasswordAuth` value now FAILs as unknown; an
  absent option (`unset`) still PASSes as the default.
- The undo of a deleted option is no longer always critical: path-option fires only when the committed value (the
  current backup for a named section, or the confirmed change's recorded diff for an anonymous `cfgXXXXXX` section)
  has a path token; unknown, masked, repeated, and section-movement values still fail safe.
- `newton-router-setup` never makes a key in place of a missing one and never touches an existing key line.
  `add-key`, `swap-key` and `lab-snapshot` make a new key only with `--new-key`; without it a missing local key stops
  the run and says the key lives on the Newton host that added it. `add-key` refuses a label that already has a Newton
  line on the router (revoke it first). First-time setup is now `swap-key --new-key newton-agent`. `add-key` also
  refuses when the key's blob is already on the router in another line, and a failed proof removes only the exact line
  this run appended.
- `newton-router-setup uninstall` still removes every Newton key line and prints each one with its `add-key` restore
  command; `check` prints `busybox unknown` instead of a blank when the router does not report its BusyBox version.

### Fixed
- The no-install read-back runs the installed router program's own internet check (ping 1.1.1.1, and openwrt.org
  resolved by the router) before every confirm, on an owner script and on an auto plan: a router without internet
  confirms nothing, the same as in the installed mode. The check waits 10 s after the apply and retries for up to 60 s,
  because the router's network reload finishes after `uci apply` returns. On an owner script the keep prompt appears
  after the check, so it can come up to 70 s after `APPLIED`.
- A change that removes a WAN port forward or a rule still asks the owner to type `keep`: Newton cannot see the live
  firewall, so a removal may still let traffic reach a service on the router itself. The prompt of such a change now
  says what silence does: the router puts the old settings back, so the forward or rule the change removes comes back.
- The keep prompt says what silence does only when the change removes something: a restore that puts the old values
  back takes nothing away, so its prompt does not say that a forward or a rule comes back.
- `newton-rpcd owner-cleanup` no longer reads the inventory, so one entry of another device that cannot be read no
  longer blocks the uninstall of this device.
- A change that Newton may not apply itself says why in plain words: a removal says that it removes a setting, and any
  other change says that it holds a change that is not on the list Newton applies by itself.

## [1.1.0] - 2026-11-02

### Added
- `newton-router-setup DEVICE no-install` and its `uninstall`: the no-install access mode for OpenWrt, where Newton
  puts nothing on the router but one limited web-interface user. It talks to the router's own web API through a pinned
  HTTPS client (the certificate is pinned), follows the transaction rules, and records the mode in the `access`
  inventory field.
- Reads on a no-install router: `newton_read` works for the reads the web API allows (config, status, logs, leases,
  ping, traceroute, nslookup) and says plainly which reads need installed access. A table of which safety checks can
  run without anything installed is part of the docs.
- Changes on a no-install router, planned over the router's own web API. A change of an allowlisted class (DHCP static
  leases and DNS entries) becomes an auto plan that names its mode, its ops and its safety checks; every other change
  becomes an owner script. The setup asks for the approval passphrase and keeps the fingerprint on the Newton computer
  only, so an approval works without anything on the router. The plan result carries the reboot line.
- The apply of a no-install auto plan. `newton_apply_change` checks the plan record before the router is contacted,
  stages the change over the router's own web API, confirms it only when every safety check passed, and answers what
  happened: `confirmed`, `rolled_back`, `not_applied` or `unknown`. `newton_change_status` and `newton_abort_change`
  answer for a no-install plan. The approval dialog and the `newton-approve` terminal show the reboot line of a
  no-install auto plan once; an owner script shows its own line once, and an installed plan shows none.
- Owner scripts. For a change Newton may not apply itself, Newton keeps a copy of the touched settings on the Newton
  computer, writes a script from one fixed template, and the owner approves its exact bytes and runs it with
  `newton-router-setup DEVICE owner-run ID`. The router's own undo timer is armed, and Newton keeps the change only
  after reading it back.
- The offer of the installed mode. The no-install setup asks the owner once whether that router should also use the
  installed mode; a "no" is remembered for that device and is not asked again, and `newton-router-setup DEVICE
  offer-installed` asks again and records the answer the same way. The two access modes, side by side and in the same
  words, are in the setup's closing lines, the installer's closing text, README.md, SETUP.md, SKILL.md and
  docs/INSTALL.md.
- The access mode of a run is measured, not declared. A lab scenario declares the mode it exercises (`access =
  "installed" | "no-install"`, installed by default). The lab runner drives the installed SSH change path itself and
  records that it ran; the no-install transport writes one line per web-API call that got an answer into the run's own
  receipt file, and the runner reads that file after every scenario. A scenario whose receipts say another mode than it
  declared is refused, and so is one that used both transports, and so is a run that mixes the modes; a refused run
  writes no results file at all. The support table takes the access mode of a recorded run from that measured fact and
  refuses a mode a run did not measure; a run without one says so instead of claiming support.

### Changed
- Fixes to the no-install path found in review. A missing section or option is "absent", not "unreadable", so a change
  that was rolled back reads back as `rolled_back` and not as "Newton cannot tell"; a window that an rpcd restart
  orphaned is answered `unknown` with the note that the change stayed, and the places that refuse a pending window say
  how to get out of it when the router kept an old undo file. A grant never covers an owner script or a critical
  change, a batch that re-types a section the router holds is refused, the ops of an apply come from the plan's own
  change and not from the record, a restore is judged against the backup of the change it undoes, an abort refuses once
  a run exists, the status answers an owner script's verdict, and an apply always leaves a run record and its result,
  even when the router fails in the middle. The probes of a plan read like the probes of an installed plan, the
  approval shows what Newton cannot check, and a setup that cannot write the approval fingerprint stops instead of
  saying it is done.
- Every command the owner is told to run is the one the installed layout can run (`sudo -u newton
  /usr/local/bin/newton-router-setup`), in the disclosure block, in the docs and in the MCP server's own messages. The
  README's, SETUP.md's and docs/INSTALL.md's SSH, new-SSH-session and three-rounds claims now say they are the
  installed mode's, with the no-install way next to them. SKILL.md's verification sentence is the installed mode's
  too, and the no-install way (the router's own web API, pinned by the certificate, no SSH round) is next to it.
- The short sentence about the uninstall names every thing an uninstall keeps on purpose. It no longer claims the
  uninstall keeps the run-time files: an uninstall stops the WAN-health check first, and that stop removes the
  WAN-health run-time state (every `*.state` file and `all_down.flag`); the directory itself stays, empty. What the
  uninstall really keeps is the saved settings and the copy of the keys from before swap-key, and those are the two
  things an owner restores by hand.
- The release plan is renumbered: 1.1 is the no-install access mode. Network promises, recipes and the network map
  move to 1.2, Linux hosts to 1.3, OpenWrt firmware upgrades to 1.4, and site files with fleet rollout to 1.5
  (`docs/ROADMAP.md`, the README, the support table).

### Fixed
- The switch from the no-install mode to the installed mode did not work, and the two modes could mix. The offer of
  the installed mode tells the owner to run `uninstall` and then `install`, but the uninstall kept
  `access = "no-install"` in the inventory while taking the login away, and the install refused every device with
  that field, so the install refused forever; the way out was a hand edit of `devices.toml` that no document
  mentioned. The uninstall now ends the no-install mode: it takes every no-install field out of the inventory
  (`access`, `rpcd_password_file`, `https_spki` and `installed_offer`), so the entry is a plain device that both
  loaders read, and the install runs on it. The install also checks the router and not only the inventory: it
  refuses, before it writes anything, while the router still holds Newton's no-install login (the `rpcd.newton`
  section), and it refuses a section that is not Newton's and a router whose rpcd config cannot be read.
- The no-install uninstall stopped when a session of the newton user timed out on its own between the listing and
  the destroy (seen on the test router). That one failure, rpcd's "Not found" (exit status 252, measured), is ignored
  now; any other failed destroy still stops the uninstall. The session listing is read in the shape measured on the
  router (one object per session with the members rpcd prints, the login name under "data", in any member order, and
  rpcd's own unauthenticated session always there) and fails closed: an answer without that shape, or an empty one, is
  never read as "no session".
- When the no-install setup could not write the inventory, it left Newton's login on the router with nothing on the
  host naming it. It now takes the login back off the router and removes the new password file (a re-setup keeps
  it: the inventory still names it), and says so when the file cannot be removed. The no-install uninstall now edits
  the inventory before it removes the password file, so a stop between the two never leaves an entry that names a file
  that is gone (the server refuses such an inventory).

## [1.0.1] - 2026-10-30

### Fixed
- `newton-router-setup <device> approval-key` said "run install first" after a refused admin login, on a router
  that had Newton installed. It now says "the admin login failed (see the FAIL line above)" under the login's FAIL line;
  "run install first" is kept for a router that answers without Newton's program.
- The skill now tells the agent to write the router's main system section as `system.@system[0]`, so Newton can
  describe a description or notes change in plain words; with the section's `cfg…` name it could not.
- A batch that also renamed or reordered something could be described as "a label only": a rename of the
  description into a working option (`log_ip`) carried no fact for the describer to see. A batch with a `rename` or
  `reorder` line is now never "a label only" and always gets "Some changes are not described here".
- The skill still told the agent to send the owner to a dialog that had timed out; it now says that dialog is dead
  and offers to ask again. The HIGH-risk second dialog's timeout now says it timed out and that a late answer is
  ignored, like the first dialog's.

## [1.0.0] - 2026-10-30

The first stable release, installed mode (Newton's program on the router). Changes since 1.0.0-rc2:

### Changed
- Approving a change is easier. The approval dialog waits 180 seconds instead of 60, and the first approval on a
  device asks only for the passphrase (or code): the warning is still shown, but the device name no longer has to be
  typed. When the dialog times out, Newton says so and that an answer typed later is ignored, even if the dialog is
  still on the screen. A change to the description or notes of the system section, written as
  `system.@system[0]`, is now described in plain words ("Changes the router's description or notes text, a label
  only.") instead of "Newton cannot describe this change".
- The router install now says what it puts on your router before it starts, and asks you to agree. The shared block
  "What Newton puts on your router" names the shell files the install uploads with their measured sizes (about 210 KB
  in 6 files, no packages, nothing compiled), the rest of the footprint (the files under `/etc/newton`, the WAN-health
  settings `/etc/config/newton_wanhealth`, the boot links `/etc/rc.d/S09newton-guard`,
  `/etc/rc.d/S95newton-wan-health` and `/etc/rc.d/K10newton-wan-health`, the `sysupgrade.conf` lines, and the one
  `authorized_keys` line that `swap-key` or `add-key` writes, not the install), why the program is there (a rollback
  that survives a reboot or a cut link, and a restricted key that can run Newton's program and nothing else) and what
  protects you: on the default `prod` profile every change needs your approval and Newton only reads until you give
  one; a router you set to `lab` applies changes without asking, except the changes Newton always asks about (22
  rules; among them SSH, the web interface, rpcd, a users or keys config, the management interface or zone, opening
  more to the WAN, and options that run commands or write files); the guard restores the last good settings; and the
  agent never gets a root shell through the restricted key once `swap-key` or `add-key` has written it (until then
  every key already on the router stays as it is, and the setup tool's own root login is the owner's, never the
  agent's). The trade-off is named too: the router runs Newton's code, so it has to be kept in step with Newton, and
  `uninstall` removes the program, the guard, the boot links, the config files, the key line and the sysupgrade lines,
  and keeps on purpose `/etc/newton/lkg`, `/etc/newton/quarantine` (the guard's saved copies of your settings) with
  the rest of `/etc/newton` (the guard's lock and log), `/usr/libexec/newton`, `/etc/config/newton_wanhealth`,
  `/etc/dropbear/authorized_keys.newton-prev` (the key line `swap-key` took out) and the `/etc/sysupgrade.conf` file
  (the Newton lines go out of it), and gives the one `rm -rf` line that removes them. The run-time files in
  `/tmp/newton`, `/tmp/owrt-safe-apply.lock` and `/var/run/newton-wan-health` are named too: they are in memory and go
  at the next reboot. The owner has to type `yes`; anything else stops the install with "nothing was changed" and the
  router is not touched. The same block stands in `README.md`, `docs/INSTALL.md` and `SETUP.md`, and `SKILL.md` says
  the same facts before the agent suggests the router install. The `lab-snapshot` action prints the same block and
  asks nothing: it only runs for a lab profile and the lab runner drives it with no owner at the terminal. The
  `upgrade` action asks nothing: it was agreed when the mode was chosen.

### Fixed
- A firmware upgrade lost the approval key, so every production change was refused afterwards until the owner ran
  `newton-router-setup <device> approval-key` again. `/etc/newton/approve.key` was not in the lines Newton adds to
  `/etc/sysupgrade.conf`, and neither was the WAN-health stop link `/etc/rc.d/K10newton-wan-health`. Both are added
  now (13 lines), and `upgrade` adds any line an older install lacks, so a router installed before this release gains
  them on its next `upgrade`; a second run writes nothing.
- `newton-install` ended every install with "Credentials were not copied. Complete these steps manually...", even on a
  fresh machine with no credentials to move, where it reads like a failure. The steps are printed on every install,
  because whether there is a credential set to move cannot be told from the installer (a development install may have
  kept its inventory anywhere). The closing text now says what the steps are for: "If you ran Newton from your own
  account before, move its router credentials to the newton account: ..." and "On a new machine there is nothing to
  move." The client command the installer prints is unchanged.
- `docs/INSTALL.md` said that three wrong answers lock the device, which holds for the approval dialog only:
  `newton-approve` counts no wrong answers and locks nothing, by design, because sudo asks for the owner's own
  password on every run (`timestamp_timeout=0`), so nothing else can try the passphrase at that prompt. The guide now
  says the count is the dialog's own and that the terminal path is protected by the owner's sudo password.
- A change that was rolled back ended with "EASY GRANT ENDED." even when no grant was ever open: the line was printed
  for the revoke attempt, not for a grant that was there. It is printed only when a grant was open and has now ended;
  an expired or malformed grant record is not a grant that was open.
- `docs/INSTALL.md` did not say how to add the router's host key to the owner's own `known_hosts`, so the doctor's
  "host key unknown or changed" had no documented fix. The text now sits after step 7d, where the fingerprint it
  compares against is printed: 7d prints the fingerprint only when the tool learned the key itself, an account that
  already knows the router has nothing to do, and otherwise `ssh root@<router>` is run once and the key is accepted
  only if the fingerprint ssh shows is the one 7d printed. A key that CHANGED means stop: the old entry is not deleted,
  and the owner is told to find out why first.

## [1.0.0-rc2] - 2026-10-28

### Fixed
- Upgrades left temporary files behind and did not restore the old install when they failed. The `--from-snapshot`
  path (the one every `newton-bootstrap install` upgrade takes) now arms the same cleanup trap as the first install:
  the launcher, sudoers and doctor temporaries and the scratch directory are removed, and an upgrade that fails after
  the code root was swapped restores the previous `/opt/newton` and says so.
- `newton-router-setup` now says why the admin login failed and how to use an admin key instead. Every admin call
  runs inside a command substitution, so ssh's own words never reached the owner: a refused root password login
  ended in a bare `STOPPED` line with no reason. The admin lane now captures ssh's stderr and prints one `FAIL` line
  before the `STOPPED` line: it names the lane, the way out (`--admin plain-key --plain-key <your admin key>` for
  the password lane, the key file for the plain-key lane) and ssh's last stderr line, escaped. Every action that
  reaches the router over the admin path (install, upgrade, check, add-key, uninstall, ...) gets the line. The line
  is only about a proven login failure: the remote command carries a fixed marker on its stderr, so an exit 255
  with the marker is the remote command's own status (a failing init script) and an exit 255 without it is a connect
  or authentication failure. Every real failure of the run is recorded in order and printed once, before the stop.

## [1.0.0-rc1] - 2026-10-28

### Added
- **Release kit.** `LICENSES/` holds the official texts of MIT, CC BY-SA 4.0, CC BY 4.0 and GFDL 1.3 (REUSE layout,
  `REUSE.toml`; `reuse lint` passes).
- **Staged-config check, router side (router program 1.3.0).** The new `check-staged <SID>` verb (helper subcommand
  `check-staged` in `scripts/owrt-safe-apply.sh`) checks the STAGED firewall config without applying it: a ucode
  wrapper points fw4's own template at the rpcd session's delta dir and `nft -c` checks the rendered ruleset, so
  nothing in `/etc/config` or the live ruleset changes. It answers exactly one line: `fw4 pass`, `fw4 fail <detail>`,
  `fw4 running-fails <detail>`, `fw4 skipped-untouched` or `fw4 not-checked <reason>`. A staged `network` change is
  never a pass (`network-live-state`: fw4 reads interface state live); a wrapper that fails, or that does not show a
  canary rule from a scratch delta dir, is `not-checked`; a vanished session is `not-checked session-gone`. The
  program holds the helper's answer to that one validated line. Measured on OpenWrt 25.12.5 only. The program hash
  changes, so lab snapshots made before 1.3.0 need `newton-router-setup upgrade`.
- **Staged-config check, host side.** `owrt-change.sh plan` asks the router program to check the STAGED config without
  applying it (`check-staged <SID>`, router program 1.3.0 and newer) and prints `STAGEDCHECK fw4
  pass|skipped-untouched|not-checked <reason>`. A staged config that fails `fw4 check`, or a running one that already
  fails, discards the staged session and refuses the plan. A router program without the verb is reported as
  `not-checked`, never as a pass. The plan record gains `staged_check` (fw4 result and the touched packages nothing
  could check) as a plan-hash field, so the owner's approval binds to it; `newton-approve` prints it and
  `newton_plan_change` returns it. Records made before this change no longer verify (plan again).
- **Undo after confirm.** The new tool `newton_plan_undo(device, change_id, explanation, owner_confirmed_in_chat)`
  plans the undo of a change that ended CONFIRMED. Newton, not the agent, builds the `uci batch`: it turns the config
  now (a fresh backup) into the config from before the change (the backup copy kept with the receipt), package by
  package, and proves the batch against a model of uci before it plans. The agent gives only `intent` and `risk`. The
  undo is a normal plan: the owner's yes in chat, the fw4 staged check, `newton-approve` (lab carve-out as for any
  plan), the rollback timer, and a receipt that says `Undo of: <id>`. It is refused, with the reason listed, when the
  change did not end CONFIRMED, was already undone, has no recorded post-change hash (confirmed before this release),
  when a package it touched differs from the state right after the change (md5), or when any later confirmed change of
  the same device touched one of the same packages. Strict: one conflict refuses the whole undo. Not undone, and said
  so: packages, passwords, reboots, client leases and associations. After a confirm, `owrt-change.sh apply` prints
  `CONFIGHASH <md5> <name>` lines before the final CONFIRMED line; the host keeps them as `after_hash` in the plan
  record (not part of the plan hash) and hides them from the agent's log and the receipt. Values are shown to the
  owner as expect claims only for `firewall`, `dhcp` and `network`.
- **Writes on VyOS, MikroTik RouterOS CHR and Junos.** One generic driver (`vendor_change.py`) with a per-vendor
  adapter arms the vendor's own undo before the first write: VyOS `commit-confirm` (T1, reload mode only), Junos
  `commit confirmed` (T1), RouterOS CHR scheduler plus binary backup (T2: undo is a reboot into the backup). Devices
  need `vendor_write = true` and key auth in the inventory. Each vendor has an allow-list lint; `newton-` names are
  reserved. The plan record carries `staged_check` as `not-checked` (no fw4 on vendors), so the approval hash binds as
  on OpenWrt. The lab driver `lab/newton-vendor-lab.py` runs the shapes in `lab/vendor-shapes.toml` against lab VMs;
  all shapes passed on a virtual image of each vendor (not hardware), recorded in `docs/SUPPORT.md`.
- **Client-vantage outcome checks.** A plan's `expect` list may hold `client_dns`, `client_dhcp`, `client_internet` and
  `client_blocked` (`to` = `router` or `internet`) claims, each naming a zone only; Newton derives the blocked
  addresses from the router's interface list at plan time and seals them into the plan hash. Each verify round of
  `owrt-change.sh apply` runs `scripts/newton-vantage-run <sid>` (the `OWRT_LOCAL_CHECK` string is built from constants
  in one place and pinned by a test), which asks a registered inside vantage to run fixed checks through a second
  forced-command key (`scripts/newton-vantage-check`, installed by `newton-vantage-setup <vantage>
  install-client-checks`, with a root-owned allow-list and a canary in the same run). A FAIL or a NOT TESTED of a
  claimed check blocks the confirm and the router rolls back; the outcome and the receipt name the claim. A claim with
  no registered vantage for its zone is refused at plan time; `timeout_s` must be at least 150. Lab scenarios:
  `ev-clientcheck-block-holds` (confirmed) and `ev-clientcheck-block-opens` (rolled back, failed claim named). The
  router program is unchanged.
- **Support table.** `docs/SUPPORT.md` is generated by `scripts/support-table.py` from `docs/support/platforms.toml`
  (undo type, the seven scenario shapes, what is untested) and `docs/support/runs.toml` (one entry per recorded lab
  run: platform, version, image or hardware, which shape scenarios passed or failed; names and counts only, no
  addresses or VM ids). `support-table.py record` appends a run from the runner's results file.
  `lab/tests/test_support_table.py` fails when the committed table is stale. A platform with no recorded run reads "no
  recorded run (untested)".
- **Change receipts.** Every apply that ends CONFIRMED, ROLLED BACK or UNKNOWN writes one readable Markdown receipt to
  `<state>/receipts/` (mode 0600): device, the plain diff, who approved and how, the checks and their results, the
  backup name and sha256, and how to undo. It is built from the plan record, the claimed approval and the host
  script's audit lines for the session (`mcp/newton_mcp/change_receipt.py`; `regenerate` rebuilds the same text),
  masked like the audit log, with the approval token and the backup's content never shown. The pre-change backup is
  copied off the script's backup directory into `<state>/receipts/backups/`. The plan record gains `backup_path` (not
  hash-bound). These are separate from the getters' field receipts.
- **Approval in the client.** The approval happens inside the client now: `newton_apply_change` raises one dialog that
  Newton builds from the stored plan, and the owner answers it with the approval passphrase or with a 6-digit code
  from an authenticator app (ADR-019). A bare accept proves nothing and is never accepted. The passphrase is checked
  against the stored fingerprint and is never written to the plan, the receipt, the audit log or any other log; a code
  is single use. The first approval on a device carries a warning and asks the owner to type the device name; the
  acknowledgement is stored. Newton never echoes an answer back in a result, an audit line or a log.
- **The second confirmation for HIGH changes.** A HIGH change (management access, internet exposure, an option that
  runs a command on the router) needs a second dialog every time. The first dialog does not stand in for the second
  one, and the second one does not replace the first.
- **Scoped grants.** The owner can allow named kinds of change on one device until a time (1, 4 or 8 hours), and
  Newton, not the agent, classes every change line: DHCP reservations, DNS settings, the router name and the Wi-Fi name
  and password. A plan that no live grant covers, and every HIGH plan, keeps the full dialog. `newton_grant_off` ends a
  grant, and so does any result that is not CONFIRMED.
- **The result line.** Every change attempt ends with one loud line, `NEWTON RESULT:` with CONFIRMED, ROLLED BACK,
  UNKNOWN or NOT APPLIED, naming the device, the session and what changed. A change made inside a grant says so on the
  same line, so an unattended change is never mistaken for an approved one.
- **The authenticator enrolment.** `newton-enrol totp <device>` shows a seed (as a QR code when `qrencode` is
  installed) and asks for a 6-digit code; nothing is stored until that code matches. `newton-enrol level <device>
  passphrase|totp` chooses which proof the device uses, `newton-enrol rotate <device>` replaces an exposed passphrase
  and `newton-enrol grant-off <device>` ends a grant. The seed never comes back through MCP.
- **The lockout after a wrong answer.** Three wrong answers lock the device for five minutes, and every further lock
  doubles the wait, up to 24 hours. The count is kept in a file under the newton state directory, so relaunching the
  server does not reset it. An answer that arrives in under a second and a half is treated as automatic, not as a
  person.
- **The doctor's new checks.** The doctor warns when Claude Code's debug logging is on, because a passphrase typed
  into the dialog is written to the debug log. It also reports whether Claude Code's managed-settings guard is in
  place: PASS when it is, INCONCLUSIVE with the line to add when it is not.
- **The dialog's time limit and the terminal fallback.** The dialog waits 60 seconds. With no answer Newton cancels,
  counts no miss and says how to approve from a terminal with `newton-approve`. That command is unchanged and is the
  fallback for a client that cannot show a dialog, cancels at once, answers too fast or is locked out.
- **The reviewer's kit.** `SECURITY.md` names GitHub's private vulnerability reporting as the way to report a
  vulnerability (no public issue and no email address) and lists the known limits. `docs/TESTING-FOR-REVIEWERS.md`
  says what to try first, what is most worth trying to break and which suites run without a network.
  `docs/assets/network-map-example.png` is an example network map with made-up addresses and synthetic MACs, and
  `pyserial` is in the test extra, so the serial suite installs with the rest.
- **The manual install guide.** `docs/INSTALL.md` is the whole install written for a person doing it by hand on their
  own machine: the same steps as `SETUP.md`, addressed as "you", with no agent instructions and no marketing. It names
  every command, flag, path and prompt, and says what to do when something goes wrong.
- **The example lab file.** `lab/lab.example.toml` ships the tables and the keys of the lab file with synthetic
  values, so a lab can be set up from the repository alone; a test keeps the example and a live lab file the same
  shape, and `docs/TESTING-METHOD.md` points a reader at the example.

### Security
- **Hardening fixes from the LOW findings.** The inventory host and user (devices and scan vantages) must match the
  getter lane's hostname and username grammar, and every ssh call (`newton_read`, `run_vantage`,
  `newton-vantage-run`, `owrt-change.sh`) puts `--` before the destination; `owrt-change.sh` refuses a destination
  that is not `[user@]host`. A device `password_file` must be a regular file (no symlink), mode 0600 and owned by the
  server user, in the inventory loader and in the argv builder. The plan record is written through a fresh
  `mkstemp` file, `fsync` and `os.replace` instead of a fixed `.json.tmp`. `newton-router-setup` shape-checks
  `NEWTON_SETUP_REMOTE_ROOT` and `NEWTON_SETUP_BIN` when the test seams are on. `owrt-change.sh` passes the router's
  `api`, `mode`, `version` and hash-prefix tokens through `oneline` in its error text. Narrowing: IPv6 host literals
  that start with `:` and scoped literals (`fe80::1%eth0`) are refused, as the getter lane already did.
- **Personal details kept out of the repository.** Real names, home network addresses and host names, lab virtual
  machine ids, local paths and production network names are not part of the repository.

### Changed
- **Release plan:** 1.0 is OpenWrt + VyOS + easy setup and in-client approvals + safety additions (staged-config
  checks, client-side outcome checks, undo after confirm, change receipts, a generated support table) + the release
  kit. MikroTik and Junos (1.1), Linux hosts (1.2), OpenWrt firmware (1.3) and site files with fleet rollout (1.4)
  follow as 1.x releases; Phases 6 and 7 are deferred. Easy mode becomes a scoped grant instead of an N-hour trust
  window, and the chat yes comes after the real diff (`docs/ROADMAP.md`).
- Docs: the README status, SKILL.md and design/02 no longer list the Wi-Fi scan as open, the router program as
  untested on a real router, or firmware as never planned.
- **The install asks about Claude Code's managed settings.** The first install asks one optional question: type
  `lock` to write `/etc/claude-code/managed-settings.json` (`allowManagedHooksOnly`, so only hooks from the system
  settings run), or press Enter to skip it. The default is no: the owner's own Claude Code hooks keep running, and every
  approval still needs their passphrase or their authenticator code. The trade-off is printed before the prompt, an
  existing managed-settings file is never overwritten, and an upgrade never asks the question and never writes the file.
- **The key label.** `scripts/newton-router-setup` enrols a router with the label `newton-agent`: the label names the
  role the restricted key plays (the agent that drives the router), not a host. A router that was enrolled before 1.0
  carries the old label, and the tool keeps that label for it: the swap adds no second key, orphans no key, and the
  upgrade of such a router keeps working. The fallback applies to the default label whether it was typed or omitted,
  and it decides from the local key files, not from a router read, so a read that fails can neither add a second key
  nor hide the key the router carries. A `LABEL` argument that is not the default is never rewritten. (The fallback is
  removed in 1.1.2.)
- **The lab scenario variables.** The scenario variables that carried the name of the agent host are renamed to
  `agent_*`: `agent_ip` and `agent_nonlocal_ip` for the agent's addresses, and the step that turns the agent host's
  masquerade on is `agent_masq_on`. An operator's own copy of a physical-router lab file must rename them too: the
  values it holds move to the new names, or the runner stops with an unknown var.

### Known limits
- **No per-device rate limit, and the fingerprint guess oracle (ADR-020).** 1.0 has no per-device rate limit on
  changes. Each production change already needs its own approval. Placeholder fingerprints let a model test a guess at a
  low-entropy secret, one planning step per guess. Use high-entropy secrets.
- **The passphrase in the client's debug log (ADR-019).** A passphrase typed into the approval dialog passes through the
  client process: with Claude Code debug logging on it is written to the debug log, and an installed Claude Code hook
  could read it. `newton-doctor` warns when debug logging is on, and `newton-enrol rotate <device>` replaces an exposed
  passphrase. Use the authenticator option (`newton-enrol totp <device>`) to avoid this: a captured code is useless a
  minute later.

## [0.8.0] - 2026-10-24

### Security
- **`newton_read` no longer runs a Wi-Fi scan.** The `wifiscan RADIO` verb was part of the shared read grammar, so the
  plain read tool could scan without the owner's consent and return neighbours' SSIDs and BSSIDs to the model. The
  tool now refuses it before any device contact and points to `newton_plan_scan(kind='wifi')`; the consented scan path
  is unchanged (`mcp/newton_mcp/server.py` `_model_read`, test `test_read_refuses_wifiscan.py`).

### Changed
- **Linux host rollback recipe verified.** `SKILL.md` "Linux host networking" is no longer marked untested: the
  timed-undo recipe passed in lab VMs on ifupdown2 (Debian 13), netplan (Debian 12, Ubuntu 24.04) and NetworkManager
  (Rocky 9). A harmless change survived a cancelled timer; a management-address lockout was rescued by the 120 s timer
  alone in 124-174 s. The recipe now covers netplan and NetworkManager files and checks that the backup exists before
  any change (a test run without it stayed locked out). The Proxmox API line stays untested.
- **Router program 1.2.0. Upgrade note:** the router program now says `version=1.2.0` (the `wifiscan` verb); `api=1`
  is unchanged. Every installed device needs `newton-router-setup <device> upgrade` after updating the host. An
  un-upgraded router refuses closed before any call, with the sha-pin message ("router program ... differs from this
  controller's ...; run: sudo -u newton newton-router-setup <device> upgrade"), so the two never talk past each other;
  the old program has no `wifiscan` at all.

### Added
- **Wi-Fi scan with the router's own radio.** The router program gains the read verb `wifiscan`: `newton-router read
  wifiscan radioN` (N = one or two digits, exactly two words after `read`) resolves the radio name to a phy with `ubus
  call iwinfo phyname` and runs one `ubus call iwinfo scan` with it, so a scan needs no netdev and works with the APs
  off. The raw ubus JSON comes back unmodified; a reply that is not `phy[0-9]{1,2}` (or an unknown radio) is
  `no-radio`, an output over 131072 bytes is `scan-too-large` (nothing on stdout, so a cut JSON is never
  half-parsed), and a ubus that is not installed is 127 and a scan over the 25 s bound is 124, the codes the other
  read verbs already use. One scan per radio per 60 s: the window is keyed by the radio name (two radio names cannot
  share one, and two radios on one phy have their own), the stamp is written before the scan so a failed scan counts,
  and the stamp is created under the program's lock so two callers at once cannot both scan.
- **Test-router lab, backup drill and client isolation.** A named backup and restore drill (`p-drill-01-backup-restore`:
  a confirmed change to the hostname, a static lease and a firewall rule, then the archive restore proves each value is
  back), and the client-isolation pair (`p-ow-wifi-05a/05b`: two stations of one USB adapter reach each other with
  `isolate='0'` and not with `isolate='1'`). All 97 scenarios pass in one run on the Asus RT-AX57M test router. Manifest
  notes for the Wi-Fi and isolation controls now say, in owner terms, what breaks; MFP works on `wpad-basic-mbedtls`
  (the old note said it needed the full wpad). The WPS on/off control stays open: the package feed no longer carries
  the router's exact wpad build.
- **Test-router Wi-Fi.** Five scenarios on the router's real 5 GHz radio, each proven from a USB client in a new lab VM
  (`lab-wifi`, Panda MT7921AU passed through, management network only): WPA3-SAE with MFP required (a WPA2-only client
  is refused), WPA2/WPA3 mixed, WPS absent from the beacon, a hidden SSID, and the ev-09 Wi-Fi config path with a real
  key. The lab runner gains `reset_after` (reset and fingerprint check after the posts), `after_reset` checks (the
  radios must be off after the reset) and secret vars (masked in results, logs, recorded vars and argv; canary tests).
  The diagnostics-read scenario's iwinfo check follows the real radio. The router's `wpad-basic-mbedtls` supports MFP but has no WPS.
- **Test-router VLAN lab.** The test router gains a second WAN (`wan2`, DHCP over VLAN 101, metric 20) and a lab client
  LAN (192.168.151.0/24 over VLAN 151, its own zone); the lab client joins it from a new snapshot. 18 more VM-lab
  scenarios are ported to the router (dual-WAN failover 13 s, failback 3 s; zones; DHCP; DNS). 18 new and 71 existing
  scenarios pass live.

## [0.7.0] - 2026-10-22

### Changed
- **Router program 1.1.0. Upgrade note:** every router must be upgraded with `newton-router-setup <device> upgrade`;
  the host refuses a router whose program differs ("... run: ... upgrade"), and approval tokens and files from before
  this release are refused (re-plan and re-approve). The approval token is now `newton-approval-v2`: its HMAC covers
  the router digest and the approval window (not-before, expiry), and the router refuses a token past its expiry by its
  own clock (`approval-window`). A router clock that is behind (no RTC, WAN down after a power cut) still accepts a
  fresh token, so the change that fixes a dead WAN can always be approved. `status` names what restored the router
  after an abort (`guard=restored:rpcd`, `restored:already-base`, `restored:guard`), and a second abort from the
  wrapper no longer overwrites it. The router refuses a `/tmp/newton` it does not own, and the guard lock lives in
  `/etc/newton/guard.lock`.

### Added
- Network-engineer mode: `SKILL.md` gains a mode the owner enters on purpose (`/newton`, or the new
  `/network-engineer` command files under `commands/` for Claude Code and OpenCode; a starter prompt for Codex in
  `docs/SETUP-CLIENTS.md`). The agent asks what to change, reads state, restates the goal, plans, waits for the
  owner's `newton-approve`, applies, reports, and asks for the next change; one change at a time, read-only asks stay
  read-only, and no existing rule is loosened.
- Lab runner, physical devices: records the router's installed package list and `/etc/apk/world` at the first reset,
  removes packages a scenario added before the `sysupgrade -b` restore, and stops if the list does not match
  afterwards; the post-restore check also covers `/etc/firewall.user`, `/etc/crontabs/*`, `/etc/rc.local` and
  `/etc/sysupgrade.conf`. Six more test-router scenarios (UPnP off/on, DNS over HTTPS, full DNSSEC, remote syslog,
  dnsmasq localservice): 71 ported, 20 still need hardware, root on the client or an owner decision.

### Security
- Field receipts are not written to a state directory that is a symlink, owned by another user or group- or
  world-writable; a state directory created by `receipts.record` is forced to mode 0700 even under a permissive umask,
  mirroring the audit log's pattern in `server.write_audit` (`mcp/newton_mcp/receipts.py` `check_state_dir` and the
  `record` append path).
- Newton's Python code now runs ssh from `/usr/bin/ssh` or `/bin/ssh` only, never through PATH, and refuses if neither
  exists (`mcp/newton_mcp/ssh_path.py`: `SSH_CANDIDATES`, `resolve_ssh()`, `SshNotFound`). Every spawn site
  (`server.read`, `scans.run_vantage`, `SshCliRunner.run`) translates `SshNotFound` into the project's normal tool
  error (`NewtonError` / `ScanError` / `RunnerRefused`) and spawns nothing. A missing ssh no longer falls back to a
  PATH lookup, so a fake `ssh` placed on PATH by an operator mistake, an installer, or a hostile shell rc file can
  never be reached. `owrt-change.sh` does the same.
- `newton-approve` escapes blank-looking characters (U+3164 and its peers, one set shared with `explanation.py`)
  instead of printing them as blanks; an inside scan target must lie inside RFC 1918 or 100.64.0.0/10 and an outside
  target must be one unicast, non-reserved address, and the approve screen says the target came from the router;
  `proxy_command` must match `[A-Za-z0-9 _./:@%~=,+-]` (it runs through `/bin/sh` inside ssh); the inventory file is
  refused if it is a symlink, not a regular file, group- or world-writable, or owned by another user
  (`mcp/newton_mcp/inventory_file.py`). **Upgrade note:** a `devices.toml` created with mode 0664 must be `chmod go-w`
  before the server will load it.
- The same inventory file checks and `proxy_command` charset now apply in `newton-router-setup`, `newton-vantage-setup`
  and `owrt-change.sh` (`OWRT_SSH_PROXY`, matched under `LC_ALL=C` so accented letters cannot pass).
- The `newton_explanation` audit line records the intent's length and a short hash, never its text, because redaction
  only catches `name=value` forms; the plan file and `newton-approve` still show the full explanation. A planned scan
  request expires 30 minutes after planning (checked at approve and at run); plan a new one. Guided setup no longer
  says a confirmation was stored when the store failed.
- Every state dir used by `owrt-change.sh` (including `NEWTON_KEYS_DIR` and the known-hosts dir) is refused when its
  parent is group- or world-writable without the sticky bit; the lab runner creates `lab/.results` and its backups
  0700 and leaves `etc/newton/guard.lock` out of the post-restore fingerprint. The receipts state dir is created 0700
  and an existing group- or world-writable one is refused.
- The plan hash now covers `reasons`, `router_leash`, `router_profile`, `router_sections` and
  `router_requires_approval`, so an edited plan file fails the hash check (`mcp/newton_mcp/plan.py`
  `PLAN_HASH_FIELDS` and the `approve._load_plan` / `server.apply` hash compare). **Upgrade note:** plans saved before
  this change are refused with "plan record was modified or is invalid"; plan again.
- `load_intents` now checks the SHAPE of an OpenWrt `control_id`: when the key is present it must fullmatch
  `OW-[A-Z0-9]{2,8}-[0-9]{2}`, so a path, a lower-case id, a one- or three-digit number, a padded value or a
  non-string is refused with "intents.toml control_id must look like OW-XXXX-NN" (`mcp/newton_mcp/guided.py`
  `_CONTROL_ID_RE` and `_validate_intent_entry`). Every control id shipped in `profiles/openwrt/intents.toml` still
  passes; an absent `control_id` (an audit-only intent) is still allowed.

### Fixed
- `newton_guided_recommend` no longer claims a confirmation record was stored when it was not: if
  `store_confirmation` raises `OSError` the result keeps every other key and `confirmation_id` /
  `confirmation_expires_at` stay `None`, but `confirmation_note` now says the record was NOT stored and that nothing
  was saved instead of repeating the stored-server-side note (`mcp/newton_mcp/server.py`). The success note is
  unchanged.

## [0.6.0] - 2026-10-19

### Added
- Consent-gated TCP scans from a registered vantage: `newton_plan_scan` plans an inside or outside scan and
  `newton_run_scan` runs it after the owner approves it out of band (`mcp/newton_mcp/scans.py`). The agent names no
  target, port, flag or vantage. Newton derives the IPv4 target from validated router reads (inside: a non-WAN
  interface's subnet, at most /24; outside: the WAN address of the lowest-metric default route, with the metric read
  from the interface so dual-WAN routes do not tie), picks the inventory's single matching vantage, and keeps only IPv4
  addresses and open TCP ports; raw nmap output, hostnames, MACs, vendors and OS data are discarded. Interface names
  must start with `[A-Za-z0-9_]`. The JSON parse path strips the read envelope's `[newton: flagged ...]` line prefix so
  a real `ubus call network.interface dump` parses; every other path keeps it. Profiles: `quick` = the top 100 TCP
  ports at 50 packets/s; `full-tcp` = all 65535 TCP ports of the router address only at exactly 300 packets/s
  (`--min-rate 300 --max-rate 300 --max-retries 0`), about 3.7 minutes, inside a 5-minute cap. `WAN_CONTROL_IDS` maps
  WAN findings to existing controls (22 -> OW-MGMT-01, 80/443 -> OW-MGMT-02, 53 -> OW-DNS-02).
- A scan that does not finish is never reported clean: `newton_run_scan` returns `result: "incomplete"` when nmap
  timed out a host, exited non-zero, was killed by the subprocess timeout, or printed no `# Nmap done at` trailer. The
  response carries the partial findings, a `timed_out` address list and a `note`, and the scan goes in
  `report_update.scans_incomplete` instead of `scans_run`. The audit line records `timed_out=<count>` and
  `outcome=incomplete`.
- Scan consent rides on `newton-approve` (`mcp/newton_mcp/approve.py`, `_approve_scan`): the owner types the same
  approval passphrase, and the consent is single-use, expires within 30 minutes, and is consumed before the scan
  starts (no retry on the same consent).
- Vantage setup and forced command (`scripts/newton-vantage-setup`, `scripts/newton-scan`):
  `newton-vantage-setup <vantage> install` lays down the restricted key, the pinned host key and the forced command;
  `check` re-verifies them. `scripts/newton-install` installs `/usr/local/bin/newton-vantage-setup` with its sudoers
  line. Inventory `[vantages.<name>]` takes `host`, `user`, `key_file`, `known_hosts`, `role` (`inside` or
  `outside`), `devices`, optional `proxy_command`, and exactly one of `admin_key` or `admin_password_file`.
  `newton-scan` is POSIX sh with four fixed nmap argv lists (no `install`, which BusyBox lacks). It lives in
  `/usr/local/libexec` for a root vantage or `$HOME/.local/libexec` otherwise; the key goes to
  `/etc/dropbear/authorized_keys` on a root OpenWrt vantage, `~/.ssh/authorized_keys` elsewhere. Install refuses
  unless `nmap`, `timeout` and `sha256sum` are on the vantage's PATH. The script travels on the install ssh call's
  stdin (no `scp`, nothing written under `/tmp`) with a SHA-256 header checked before it replaces anything; header
  lines and paths are validated before any filesystem change; the bin directory is forced to 0755/0700 and verified,
  so a pre-existing world-writable one cannot let another user swap the forced command; the replace uses `mktemp` in
  that directory; a missing final newline in `authorized_keys` is added first. `check` matches the forced command's
  refusal exactly and, when it fails, names the likely OpenWrt cause (no root password lets dropbear accept any login).

### Changed
- README.md and `docs/SETUP-CLIENTS.md` list the install prerequisites (`sudo`, `git`, an ssh client, Python 3 with
  `venv`). A fresh-machine install on Ubuntu 26.04 found `python3-venv` missing from the docs; everything else
  installed and ran as documented.

## [0.5.0] - 2026-10-18

### Added
- Multi-vendor read-only getters (tier T0-exp): `newton_get_state` and `newton_list_getters` read a fixed allowlist of
  `show`-style commands from Cisco IOS XE, FortiOS, Junos, EOS, VyOS and RouterOS devices over a locked OpenSSH exec
  channel (`mcp/newton_mcp/adapters/ssh_cli.py`): no PTY, stdin closed, pinned `known_hosts`, a byte cap, a 30 s hard
  timeout, a five-second per-device rate limit, and an auth-failure disable marker. Devices must set
  `experimental_readonly = true`; results carry an "experimental" caveat and `device_role_enforced = false`.
- Explain before every getter read: every multi-vendor getter row gains `why` (what the read is for) and `expect` (the
  output shape it should have). `newton_get_state` reports `shape` as `matched`, `mismatch` or `not_checked`. The
  matcher is a linear token line-shape matcher, not a regex (an earlier regex draft could be made to run for minutes
  on hostile output). The old `success_marker` field is folded into `expect`.
- Field receipts: every getter run appends one line (platform, OS version learned from the device's own `version`
  read, getter id, status, shape, UTC date) to `field-receipts.jsonl` in the state dir (0600, capped at 512 KiB with
  one rotated copy). No device output, name or address is stored. `newton_list_getters` shows per-OS counts as field
  evidence, not verification. `NEWTON_FIELD_RECEIPTS=0` turns it off. `expect` entries are capped at 12 `||`
  alternatives.
- Per-vendor secret redaction (`mcp/newton_mcp/adapters/platform_redact.py`) runs before the shared redactor on every
  getter result.
- Lab receipts: RouterOS (CHR 7.24.5) and VyOS (2026.10.01-0035-rolling) getters are recorded on lab VMs and pinned to
  those versions, with recorded fixtures under `mcp/tests/fixtures/vendors/*/recorded/`. The other vendors stay
  `unverified`. `running_config` is disabled on every vendor, and so is the RouterOS `admins` getter.
- Explain before every change: `newton_plan_change` and `newton_plan_tier` now require `owner_confirmed_in_chat=true`
  and an `explanation` object (`intent`, `steps` with one entry per change line, `expect` with 1-8 structured claims,
  `risk`). A claim is either a `uci_equals` claim or one of the existing probes, validated by the real probe table;
  nothing is free-form or executable. Text is printable only (control characters are refused), secrets are masked, and
  both fields are inside the plan hash, so changing the explanation needs a new plan and a new approval.
  `newton-approve` shows Newton's own facts first, then "Agent's explanation (unchecked claims)", and flags steps that
  name sections Newton did not touch or touched sections no step mentions. SKILL.md has the new Step 0 rule.
- Expect claims run after apply: the agent's `expect` claims now run after apply. Each claim becomes a sealed probe
  appended after Newton's own probes and the caller's probes, so a claim can only add a check, never remove or weaken
  one. A false claim means the change does not confirm and the armed rollback restores the router; the result's
  `failed_claim` names the claim, read only from the `stage=router-verify` failed-round header of the apply output,
  and only for a router failure reason from its fixed vocabulary (for example `mismatch`, `absent`, `count=N`).
  `newton_plan_tier` now leaves room for 8 claims per batch: standard plans as 1 batch, hardened and lockdown as 2.
- Lab runner, physical devices (`lab/newton-lab-test.py`, `lab/pulsar.example.toml`): before it changes anything on a
  physical router the runner proves which router it is (`/etc/newton/device-id`, `/etc/newton/profile` = `lab`, board
  name) and stops on a mismatch; it restores the router from a `sysupgrade -b` baseline archive that is sha256-pinned
  and validated before any file is deleted. New outcome `rebooted_restored` (the router rebooted inside the window and
  the guard restored the config at boot). 65 scenarios in `lab/scenarios-pulsar/`: 64 pass live on the Asus RT-AX57M
  test router (2026-10-18); `p-ow-upd-02-owut-check-audit` fails because the upstream `owut` tool crashes there.

### Changed
- Upgrade note, approval: every change now needs the owner's out-of-band `newton-approve`, not only the ones the
  profile or leash flagged (`mcp/newton_mcp/approval_gate.py`). A device that sets both `profile = "lab"` and
  `lab = true` keeps the old rule, so lab scenarios still run; an OpenWrt `profile = "lab"` device without `lab = true`
  now needs approval for every change, so add `lab = true` to lab routers. The lab carve-out is one switch
  (`LAB_APPROVAL_CARVEOUT`, ADR-018). Plans saved before this change have no explanation and are refused at apply and
  approve: plan them again.
- Plan records carry `explanation` and `owner_confirmed_in_chat` in the plan hash fields; `apply` also refuses a
  stored plan that lacks a valid explanation or says no approval is needed on a device outside the carve-out.
- VyOS getters run through the fixed `/opt/vyatta/bin/vyatta-op-cmd-wrapper` path: VyOS runs exec-channel commands in
  vbash, which has no operational mode, so a bare `show` fails there.
- `scripts/owrt-change.sh`: the failed-round `VERIFY DETAIL` header now prints the real exit code (it printed the word
  `rc`) and names its stage: `stage=router-verify`, `local-check` or `logd`.

## [0.4.1] - 2026-10-17

Upgrade note: `newton-approve` now refuses when no approval fingerprint is on record for the device (installs set
up before fingerprints existed have none). Run `sudo -u newton /usr/local/bin/newton-router-setup <device>
approval-key` once and type the same approval passphrase: it prints `PASS approval key already set`, leaves the
router unchanged and records the fingerprint.

### Added
- `newton_guided_recommend` (`mcp/newton_mcp/guided.py`): with no answers returns the ten interview questions as `{id, text, answers}`; with answers returns a `guided_setup_report` whose recommendations and statuses (`plan-ready`, `audit-only`, `skipped`, `gap`) are DERIVED from the manifest and the three tier files. The tool never contacts a device, never accepts a tool path / command / file / device argument, and never plans. Interview answers are recommendations only; no batch is approved.
- `newton_guided_audit` (`mcp/newton_mcp/guided.py`): runs the fixed six-item read-only audit (listeners, services, port forwards, UPnP, Wi-Fi settings, DHCP devices) for one device through the existing `newton_read` path; every result stays inside an `untrusted-device-data` envelope and the services item records the gap (no closed running/enabled-service read). The tool performs no scan and makes no changes.
- SKILL.md: new `## Guided setup` section that documents the flow (recommend / audit / plan / approve / apply), states plainly that interview answers are recommendations and never approval, and lists the four scans (nmap inside, nmap outside, Wi-Fi scan, kismet) as not available yet pending the owner's consent record.
- Note: scans are not part of this change. The four scans stay under `scans_not_run` in the report; `newton_guided_audit` and `newton_guided_recommend` neither run nor suggest any scan tool or command.

### Fixed
- `newton-wan-health.sh`: moving a WAN's default route no longer deletes the live route unless the replacement route is confirmed present, so a failed `ip route add` cannot leave the router without a default route (demote and restore).
- `newton-wan-health.sh`: the all-down guard counts only active WANs, so an inactive WAN's stale "up" mark cannot disable it.
- `newton-wan-health.sh`: a route metric with a leading zero (such as `08`) is rejected instead of crashing the shell arithmetic.
- `newton-wan-health.sh`: stopping the idle loop with TERM or INT now restores demoted routes before exiting.
- `newton-router-setup`: when a first install fails, the WAN-health service is stopped and disabled before its files
  are removed, so no daemon is left running without its script.
- `newton-router-setup`: `upgrade` restarts the WAN-health service after the new files are verified, but only when the
  service was already enabled and one of its two files changed. A disabled service stays stopped. An upgrade that
  changes nothing does not restart it, so a WAN the service took down as dead stays down.
  If that restart fails, the setup host keeps a per-router note of it, so running `upgrade` again retries the
  restart instead of reporting success while the old code still runs.
- `newton-router-setup`: when a failed install cannot stop or disable the WAN-health service, the failure note keeps
  what was restored and names the WAN-health files left on the router.
- `newton-router-setup`: `rollback` also restores the WAN-health script and init from their `.prev` copies. `uninstall`
  removes those `.prev` copies.
- `newton-router-setup`: `rollback` and `uninstall` clear their device's host-side WAN-health restart-pending marker
  after the router-side restore/removal; a cleanup failure prints `FAIL` without undoing the action.
- `newton-router-setup`: a failed WAN-health `stop` is no longer hidden by the `disable` after it. Uninstall stops
  there and removes no code files.
- MCP: when `fw4 check` already fails before a plan, the router's text now comes back inside the untrusted-device-data
  envelope, like other router output.
- MCP: `staged_at` is now part of the plan hash, so editing it in a stored plan makes approve and apply refuse the plan.
  Plans saved before this change are refused ("plan record was modified or is invalid; plan again"); plan again.
- Host policy: a new section whose type the diff masker hid (`<masked>`, `<redacted:…>`) counts as unidentified and needs approval (it was free on the host; the router leash still fired).
- `scripts/newton-serial.py` console output is now framed between
  `----- BEGIN/END UNTRUSTED CONSOLE TEXT <token> -----` lines (random token per call,
  device-cannot-forge, C0/C1 controls, U+2028/U+2029 and every Unicode format (Cf) character, bidi marks included, escaped inside the body); the
  `STATE:` / `REMOTE-EXIT:` / `EXIT-STATE:` trailers move to stderr. Transcripts use a 0700
  leaf directory and 0600 files (umask-independent); a symlinked or foreign-owned --log-dir
  is refused before anything is opened.
- MCP, `scripts/owrt-change.sh`: the apply outcome classifier splits the script output on LF only (Unicode line separators and other control characters in router text no longer start a new line), and `oneline` turns U+2028, U+2029 and U+0085 into spaces and masks `APPLIED`, so router text cannot forge an `APPLIED session=` line.
- MCP redaction: secret names are lowercased and `-` becomes `_` before the catalog tests, so `private-key`, `wpa-psk` and `sae-password` (JSON or free text) are redacted; the catalog adds `authorization`, `proxy_authorization`, `cookie`, `set_cookie`, `sysauth*`, `ubus_rpc_session`, `param_enc`, `auth` (exact, suffix and contains), and `sid` in the `sid:` and JSON forms only (the router status line `pending sid=… guard=… rpcd=…` and Newton's syslog line pass unchanged); an unquoted value after a secret name outside a URL query now runs to the end of the line. Options that merely contain `auth` now show as placeholders, except a catalog `allow` list (`authoritative`, `auth_server`, `auth_port`, `auth_cache`, `acct_server`, `acct_port`, `rsn_preauth`, `maxauthtries`, `no_ubusauth`) that both maskers check first. The placeholder-mismatch error now puts its explanation before the quoted batch line.
- MCP (`newton_apply_change`, `scripts/owrt-change.sh`): the approval record is now marked `.used` only AFTER the apply script reached the router. The host first CLAIMS the record (rename `<sid>.json` -> `<sid>.claimed`) and then SETTLES it after `run_script` returns: if stdout contains the exact `APPLYING session=<sid>` line (the signal `owrt-change.sh` logs right before it ssh's the helper) the claim becomes `.used`; otherwise the claim is released back to `.json` so the human approval can be reused on the next apply call. A `subprocess.TimeoutExpired` is treated as reached (outcome unknown). Pre-router failures (stale base, ssh refused, health-snapshot failure, missing helper) no longer burn the approval.
- MCP (`newton-approve`): a missing approval fingerprint is now a refusal with a clear remediation message, not a notice. The previous behaviour wrote an approval whose token the device refused (bad-approval) and burned the human approval. Approve now refuses until `newton-router-setup <device> approval-key` is rerun.
- MCP (`newton_plan_change`): `staged_at` is now stamped BEFORE the plan script starts (it was stamped after), so the host's stage-expiry cap is never later than the router's (the router counts from stage-up at stage time). An approval at the edge no longer fails with stale-stage and burns the human approval.
- MCP: an unexpected error in `newton_guided_recommend`, including a failed import of the guided module, is logged to
  `mcp-errors.log` and answered with the same "internal server error" as every other tool.
- Lab: `dw-01`, `dw-02` and `dw-05` fail when failover or failback takes longer than
  `count*(interval+targets*timeout)+interval` seconds (each dead round pings every probe target in turn), computed
  from each scenario's settings (26 s failover at the defaults with one target, 32 s with two). ADR-017 and SKILL.md
  state the budget. The lab tests run each scenario's check with too-slow and in-time timings.
- Tests: the WAN-health script tests run under busybox ash, the router's shell, instead of host dash.

## [0.4.0] - 2026-10-16

### Added
- `scripts/newton-wan-health.sh` (with a procd init script): a router-side dual-WAN health check. It probes each WAN
  with `ping -I <device>`, and when one is dead it moves that WAN's default route to a higher metric at runtime only (no
  UCI or `/etc` writes, so config hashes do not move on a flap), then restores it after the WAN recovers. Settings come
  from the UCI package `newton_wanhealth` and are enabled through a normal Newton change (`newton_wanhealth` is a known
  package since router 1.0.3; a prod router still needs approval for every write). `scripts/newton-router-setup`
  installs, verifies, checks and uninstalls it.
- Five dual-WAN lab scenarios in `lab/scenarios/dualwan/`: failover, failback, no failover without the service, no flap on
  one dropped probe, and failover on `ifdown`. The upstream is cut on the lab ISP VM only; traffic is observed with its
  packet counters, not the internet.
- Lab scenario `everyday/ev-10-fw4-already-broken`: with `fw4 check` already failing, the apply is refused by the
  router-side health gate, and `read fw4 check` over the restricted key answers exit 1. The lab runner treats the health
  gate's refusal as `refused`. (The MCP text "fix the firewall first" is only unit-tested; the runner does not use MCP.)

### Changed
- Router program `newton-router` 1.0.2 -> 1.0.3. Installed servers still run 1.0.2 until you re-install.
- `newton-router-setup` puts the WAN-health script, its init and its `rc.d` link in `/etc/sysupgrade.conf`, so they
  survive a sysupgrade; a failed upgrade restores the previous health files instead of deleting them.
- Dual-WAN failover is netifd metrics plus the health script, not mwan3 (ADR-017; design docs 06, 09, 10 reworded).

### Fixed
- `newton-router abort` removes `/tmp/owrt-safe-apply.lock/sid` when it names the aborted session (a different SID is
  left alone).
- `newton-router read <tool>` for a tool that is not installed (for example `iwinfo`, `wifi`, `apk`) answers
  `error tool-missing NAME` with exit 127, not the program's path and a shell line number. `grammar.tsv` lists 127.
- The probe `conf-has dnsmasq ...` also reads `/tmp/hosts/dhcp.<id>`, where dnsmasq keeps `dhcp domain` records, so a
  plan that checks a local DNS name no longer rolls back a correct change.
- `newton-doctor --device NAME` no longer ends INCONCLUSIVE for a good router: `newton-router-setup NAME check` now
  prints the two restricted-key proof lines the doctor reads (a WARN line, no proofs, when no key is installed).
- `newton-approve`: a fingerprint file with a non-ASCII byte counts as a wrong passphrase, not a traceback; a staged
  change that expired while you typed is refused ("plan it again"); the "Approved ... for N minutes" line shows the real
  window. `newton-router-setup approval-key` removes the old fingerprint before writing the new one, so a failed write
  cannot leave a stale fingerprint that refuses the right passphrase.
- `owrt-change.sh` no longer leaves `LC_ALL=C` set for the rest of the run after its control-character check; ssh and
  the other tools it starts now see your own locale setting.
- `owrt-change.sh backup` no longer builds a backup file name that starts with a dot: a router hostname of `..`, `.`
  or `../x` gives a name starting with `_` (slashes were already replaced, nothing was written outside the folder).
- `newton_plan_change` now refuses up front when `fw4 check` already fails on the router before any change ("fix the
  firewall first", with the first lines of its output, masked). Before, the plan and approval went ahead and the
  apply was refused later. Only fw4's own failure (exit 1) refuses; a timeout or ssh error lets the plan continue.

## [0.3.2] - 2026-10-16

### Added
- Nine everyday-change lab scenarios in `lab/scenarios/everyday/`: a static lease that is really served, removing and
  changing a port forward, a local DNS record, a DNS upstream change, a user firewall allow and block rule, the
  `read` diagnostics, and a Wi-Fi change on a router with no radio (config path only, not a Wi-Fi test).

### Fixed
- `newton-approve` now checks the approval passphrase against a fingerprint that `newton-router-setup
  approval-key` stores in the state dir (`approval-fp/<device>`), and refuses a wrong one at approve
  time instead of at apply; if no fingerprint is stored it says it could not check (re-run
  `approval-key`).
- `newton-approve` prints `Stage expires:` (the router refuses a stage older than 2700 - timeout - 60
  seconds), refuses an already-expired stage, and the approval's `expires_at` is never later than the
  stage expiry; plan records now carry `staged_at`.

### Changed
- The installed `newton-mcp` launcher sets `OWRT_BACKUP_DIR` and `OWRT_AUDIT_LOG` to the state dir
  (`<state>/backups`, `<state>/audit.log`). Older backups and audit entries stay where they were,
  under the old default `$HOME/.local/state/network-agent/` of the `newton` user
  (`/var/lib/newton/.local/state/network-agent/` on an installed system); nothing is moved. Plans are
  still written under that old path.
- `newton_plan_tier` and `newton_list_tiers` descriptions now say a placeholder like `{fw_wan_zone}`
  wants the UCI section id (e.g. `@zone[1]` or a named section id), not the zone's name option.

## [0.3.1] - 2026-10-15

### Fixed
- An installed MCP server could not plan any change or list tiers ("internal server error"): it looked for its
  profiles next to the Python packages instead of under `NEWTON_HOME`. It now uses `NEWTON_HOME`.
- The installer now installs the three tier files (`standard.uci`, `hardened.uci`, `lockdown.uci`) next to the
  manifest.
- The `newton-mcp`, `newton-approve` and `newton-router-setup` launchers now start in `/` instead of the caller's
  directory (an unreadable directory crashed the server at start; a writable one let the caller plant server
  settings). Give `newton-router-setup` absolute paths: a relative one now resolves from `/`.
- Unexpected tool errors now write their traceback to `mcp-errors.log` in the state dir (mode `0600`); the agent
  still sees only "internal server error".
- New test (`mcp/tests/test_installed_layout.py`) that installs the package non-editable and checks the paths
  resolve under `NEWTON_HOME` (the gap that hid this).

## [0.3.0] - 2026-10-15

### Added
- Hardening tiers through MCP: `newton_list_tiers` and `newton_plan_tier` (`mcp/newton_mcp/tiers.py`). A tier is
  split into ordered batches that each fit the router's 32-check limit, and every batch goes through the normal
  plan, approval, apply and confirm path; there is no tier-apply tool. A failed batch rolls back only itself.
  Placeholder values (`{fw_wan_zone}` etc.) must be given explicitly and are validated; nothing is looked up.
  Lab-only and package-conditional controls are listed as skipped, never planned.
- Lab runner: tier scenarios (standard, hardened, lockdown) with a reboot step (boot-id proof), survival checks
  after the reboot and a rollback check (`uci export` hash equal before and after).

### Fixed
- Docs named the development command for MCP registration; the installed server is registered as
  `sudo -n -u newton /usr/local/bin/newton-mcp`.
- A protocol test failed on any host where Newton was installed (it read the real bootstrap path).

## [0.2.0] - 2026-10-14

First formal release.

### Added
- Every change runs the live checks of the profile controls it applies (ADR-010, `mcp/newton_mcp/touched.py`):
  a setting the router silently ignores no longer confirms (`ow-dns-04a` now rolls back). 22 controls are checked
  automatically; the 25 that cannot be are listed in SKILL.md. A plan whose checks exceed the router's limit is
  refused with the control ids named, never trimmed.

### Changed
- Router program `newton-router` 1.0.1 -> 1.0.2.
- A change that reloads or restarts rpcd stays rollback-only (measured: confirm returns 251 after an rpcd reload).
- The after-rollback ALERT says "was not compared" when the router could not compare health, "differs" only when a
  comparison ran.

## Before this changelog (2026-10-03 to 2026-10-14)

Early work on the safe apply path, in short:
- **Safe apply protocol:** stage, apply with rollback, confirm; every verify round checks that services still run and
  have not restarted and that `fw4 check` passes; router and check text cannot forge an outcome line.
- **Safety kernel:** the MCP server is the only write path and runs as its own `newton` user that owns the router
  credentials; the owner approves in their own terminal (`newton-approve`), bound to the plan hash and the router's
  config hash; secrets are redacted from everything the model sees; router data comes back marked untrusted; changes
  to Newton's own access path need out-of-band approval.
- **Reboot-safe rollback:** a guard on the router keeps the last-known-good config on flash and restores it before
  the network starts at boot.
- **Install:** `scripts/newton-install` (first install) and the root-owned `newton-bootstrap` (every later update,
  from a verified commit).
- **Profiles:** Standard, Hardened and Lockdown tier files generated from `profiles/openwrt/manifest.toml`.

[Unreleased]: https://github.com/kevwillow/newton-senior-engineer/compare/v1.1.3...HEAD
[1.1.3]: https://github.com/kevwillow/newton-senior-engineer/releases/tag/v1.1.3
[1.1.2]: https://github.com/kevwillow/newton-senior-engineer/releases/tag/v1.1.2
