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

## [1.6.1] - 2026-11-27

### Added
- The recipes: a common router job asked for by name ("add a guest network") is planned from a reviewed recipe file,
  `profiles/openwrt/recipes/<id>.toml`, instead of a hand-written UCI batch. The file holds a header, typed parameters,
  the steps that write the change, the checks that prove it, the packages it needs and the risk the approval text
  carries. It is not a device profile, no tool writes one, and a recipe never adds a network rule: only the owner
  writes those (`newton-rules`), and a recipe may suggest one.
- Two tools: `newton_list_recipes(device)` lists the recipes of the device's platform, each parameter with its kind,
  its help and its default, and each step with its UCI lines and their placeholders (a read of the host's own files; it never contacts the device, and a recipe file that does
  not load is listed with its error, never skipped), and `newton_plan_recipe(device, recipe, values, timeout_s,
  explanation, owner_confirmed_in_chat)` plans one recipe by name. The server has thirty tools now.
- Every value is checked by the kind of its parameter before any device call: `ipv4`, `cidr4`, `mac`, `hostname`,
  `name`, `iface`, `wifi_ssid`, `wifi_key`, `wg_pubkey`, `choice` (a fixed list) and `int` (a range). A refusal names
  the parameter and never the value. On an installed OpenWrt router the resolved batch and the resolved checks then go to the same `plan()`
  every other change uses: the seal, the ADR-010 touched checks on the resolved lines, the network rules, the approval gate, the
  leash, the hold and the undo all apply unchanged.
- The seven recipes: `guest-network` (a separate network for guests or IoT devices, wired, Wi-Fi or
  both), `dhcp-reservation` (one device always gets the same IPv4 address), `port-forward` (a service inside your
  network answers on a port of the outside interface), `dns-host` (one local name answers with one IPv4 address),
  `dns-upstream` (version 2: the router forwards every DNS question to the servers you name), `wireguard` (one peer reaches your
  network through a tunnel on the internet side) and `bufferbloat` (the traffic of the WAN device is shaped to the
  speeds you give).
- The lab runner's recipe scenarios: a scenario may name a recipe instead of carrying a batch. `lab/scenarios/recipes/`
  holds eight of them (rc-01 to rc-08), one per recipe plus a fresh router for the dns-upstream recipe. All eight
  confirmed on lab-r1 on 2026-11-27, rc-01 with the owner's four rules about the guest zone (the zone
  reaches the internet, names resolve through the zone router, the router's own addresses stay blocked, the zone
  reaches the router's own DNS). `lab/scenarios` holds 108 scenario files.
  The live runs found two faults in the dns-upstream recipe before release: a delete of a missing entry fails the whole
  uci batch on a stock router, and a plain option (not a list) is skipped by dnsmasq's init. The recipe now writes a
  list, and its checks read dnsmasq's generated conf, so a batch dnsmasq ignores cannot confirm.
- The router program is unchanged (1.3.4): no `newton-router-setup upgrade` is needed.

### Known limits
- On a router Newton cannot install on (no-install mode) a recipe takes that mode's own path, which carries neither the
  recipe's own checks nor its risk line, and reads no package and no set path (the plan says `preconditions_unchecked`).
  There Newton applies the DHCP reservation and the local name itself; the port forward, the DNS servers and a wired
  guest network become an owner script; a guest network with Wi-Fi and the WireGuard tunnel are refused, because a
  script never carries a key; bufferbloat is refused, because that mode cannot read the `sqm` config.
- The bufferbloat recipe writes the `sqm` config, which is not in the list of configs Newton knows: its plan on an
  installed router carries an `unknown-package` reason.
- Newton never installs a package. The owner runs the `apk add` line the refusal prints.
- The WireGuard private key is made on the router by the owner's own command (`owner_command` in the recipe). Newton
  never makes it.
- The port-forward recipe does not check that the inside address is on the LAN.
- The guest network's DHCP range starts at host 100 and holds 150 addresses, which fits a `/24` or a larger network:
  give it one of those (a smaller network was not tested).
- Give the guest network a wired port, a Wi-Fi name, or both: with neither, the plan builds a network nothing can join.
- The guest network's wired port must be one no other bridge uses, like a VLAN device (`eth3.30`). On most routers
  the LAN ports (`lan1` to `lan4`) are in `br-lan` already, and the recipe does not take a port out of `br-lan`: take
  it out first, or use a VLAN device.
- The recipes are OpenWrt only. The Active Directory recipes are 1.6.2.

## [1.6.0] - 2026-11-27

### Added
- The owner's network rules join every change of an installed OpenWrt router. The rules live in `rules.toml` next to the
  inventory and only the owner writes them (`scripts/newton-rules`, shipped in 1.1.3); until now the file was stored and
  no change read it. Every rule of the device becomes a sealed client check, run from the registered inside vantage of
  the rule's zone, in the same verify rounds as the agent's own client claims. The rule kinds are `dns`, `dhcp`,
  `internet`, `blocked` (the router, the internet, or one address and port) and `reach` (one address and port). A rule
  that fails means no confirm: the router rolls the change back at its deadline. A rule that cannot run refuses
  the plan before anything is staged: no vantage for the zone, a broken `rules.toml`, a device whose mode cannot run them
  (no-install, the vendor platforms), or a target the vantage may not probe (outside its `check_targets`). The reads still work.
- The approval text lists the rules checked on the change: "Your network rules checked on this change:", one line per
  rule with the rule's sentence and its label.
- `hold` works with client checks. `newton_confirm_change` runs the sealed client checks again right before it confirms;
  a failure refuses the confirm and the router rolls the change back. The confirm trusts only the sealed plan record: a
  missing record or a hash mismatch refuses it.
- The lab runner has four new scenario fields: `rules`, `hold`, `before_confirm` and `expect_confirm_refused`.

### Changed
- A plan with client checks takes a `timeout_s` of 150 when the caller names none; an explicit lower value is refused.
  The rules' claims do not count against the agent's own eight claims, so a device may carry rules and agent claims in
  the same plan. `newton_plan_undo` and `newton_plan_tier` work on a device with rules.
- The router program is unchanged (1.3.4): no `newton-router-setup upgrade` is needed.

### Verified
- The network rules on the lab VM, 2026-11-27: lab-r1 (OpenWrt, router program 1.3.4) with the lab
  runner's scenarios `lab/scenarios/everyday/ev-rules-01..04`. 01 confirmed with four rules checked (internet, dns, the
  router blocked, reach); 02 a change without the guest-to-WAN forwarding rolled back on the internet rule; 03 a held
  apply confirmed; 04 a held apply whose client lost its route before the confirm: the confirm was refused ("the local
  check failed before the confirm") and the router rolled the change back. The live run found the gap of a target the
  vantage may not probe; it was fixed before this release.

## [1.5.2] - 2026-11-26

### Added
- The change protocol, written once: `docs/design/13-CHANGE-PROTOCOL.md` names the ten rules every change follows
  (the owner's yes, the plan sealed at plan time, the approval bound to the plan's digest, the diff unchanged from plan
  to apply, the undo armed before the write, the verify over fresh connections, the confirm only after a verified
  record, a fixed set of outcomes, the running state shown after a restore, a lost controller) and, for each rule and each
  mode (OpenWrt installed, OpenWrt no-install, VyOS/Junos, MikroTik CHR, AD write, AD build), the tests that prove it
  or the reason it cannot apply. A checker test (`mcp/tests/test_protocol_contract.py`) fails when a cited test is
  missing, a cell is empty, or a gap has no entry. Every gap is closed in this release.
- The approval text has one "If Newton loses contact:" line for each mode, saying what the device does on its own.
- Installed OpenWrt: after the router's guard put a change back on its own, `newton_change_status` says whether the
  running network matches the restored settings (`running`: `match`, `differs`, `unproven` or `boot`). For `differs`
  and `unproven` it adds a `next_step` with the command that makes them match
  (`reload_config; /etc/init.d/firewall restart; wifi reload`). Newton reads only its own fixed line from the host
  output, so a router cannot put words into these fields.
- No-install OpenWrt: a change the router's rpcd timer rolled back says `running: unproven` and the same `next_step`.
- The lab runner can kill its controller in the middle of a change (`controller_loss = "verify-1" | "verify-2" |
  "confirm"`) and judges the router afterwards; three Pulsar-lab scenarios use it.

### Changed
- `newton-router` 1.3.4: `verify` records its passes, and `confirm` refuses (exit 3, `not-verified`) without three
  recent passes on this boot. The health check and the verify round close five holes; among them, a health snapshot can no
  longer be replaced after the apply or while it runs, a standalone health check drops only its own session's
  record, and the DHCP check of a router only ever gets stricter. Re-run `newton-router-setup` to install it.
- No-install OpenWrt: the list of checks is now part of the sealed plan hash. A no-install plan saved by an earlier
  release no longer verifies: plan it again and approve it again.

### Fixed
- No-install OpenWrt: a plan record whose explanation claims were swapped (with the hash recomputed to match) was
  applied. The apply now checks that the claims are the record's sealed probes, as the installed and vendor applies
  already did, before the router is contacted.
- No-install OpenWrt: a plan record whose list of checks was edited on disk was applied (see Changed).

### Verified
- Rule 10 on a real router, 2026-11-26: the lab router (GL.iNet GL-MT3000, OpenWrt 25.12.6, `newton-router` 1.3.4)
  with the controller killed at the first verify, the second verify and the confirm. All three runs ended with the
  guard restoring the base and `running=match`. No run showed `running=differs`, so the fix command was not exercised
  on a router. Everything else in this release is covered by tests on fakes.

## [1.5.1] - 2026-11-25

### Fixed
- AD build mode: a state directory with no room left (a full disk, an exhausted quota) no longer makes
  `newton_ad_build_run` raise. The run state is written once before anything is sent; when that fails the run stops
  `state_unwritable` and nothing goes out. A save that fails later stops `state_write_failed`, names the stage and
  device, frees the run lock, and says the helper's journal on the server holds what ran; calling again after freeing
  space does not repeat a stage the journal records as done. **Covered by tests only** (fakes that raise ENOSPC).
- AD write setups, Windows and Samba: a domain controller that already holds a different approval key no longer says
  "Nothing was changed". The setup creates the newton-ops account and its delegation before it reaches the key, so it
  now says the key was not changed, the setup stopped, and those earlier steps have already run.

## [1.5.0] - 2026-11-24

### Added
- Active Directory build mode (opt-in): `newton_ad_build_plan`, `newton_ad_build_run` and `newton_ad_build_status` build a
  new domain with two domain controllers on two fresh Windows Server 2025 servers, in stages 0 to 10, from one plan the owner
  reviews and approves with `newton-approve`, and a fresh approval before each stage that asks for one. A helper on each
  server runs the stages and keeps a journal; a Proxmox or Hyper-V checkpoint is taken before each write stage. The stages:
  base settings and features, the forest, the AD Recycle Bin, the Windows LAPS schema, the structure (OUs, groups, the
  owner's admin account in Domain Admins and Protected Users and not delegated, the password policy, a fine-grained policy
  for tier 0 admins, the machine account quota 0, the built-in Administrator disabled or given a random password by plan
  option), the baseline GPOs (including Windows LAPS for the domain controllers with the encrypted DSRM password backup),
  the second controller by offline domain join with replication checked both ways, the newton-audit and newton-ops logins,
  the build account removed, and Newton's own Active Directory audit as the acceptance: stage 10 stops on any finding
  outside the plan's accepted list. One build runs at a time per state directory. **Measured:** one full build passed
  stages 0 to 10 on Windows Server 2025 evaluation VMs on Proxmox (2026-11-24). Not measured: the Hyper-V checkpoints on a
  real Hyper-V host. Never run it on an existing domain.
- `newton-ad-discover --preflight`: an opt-in preflight of every domain controller the tool found, read-only, from the host
  the tool runs on. It connects to the ports 22 (SSH), 389 (LDAP) and 88 (Kerberos) with a 3 s timeout each (the connection
  is closed at once, nothing is ever sent) and reads the clock of the controller with one SNTP query on UDP 123 (over IPv6
  when the address of the controller is an IPv6 address): a 48 byte client packet (mode 3) whose transmit timestamp holds
  the local time and a random fraction, and a reply that is only accepted when it is exactly 48 bytes long (up to 512 bytes
  are read, and any length other than 48 is refused, so a longer datagram is not trimmed to a length that looks right),
  comes from a time server
  (mode 4) whose clock is synchronized (leap indicator 3 is refused), has a stratum of 1 to 15, carries a transmit
  timestamp that is not all zero (bytes 40..47; RFC 4330 section 5 check 4: such a reply is discarded, so the clock is
  UNKNOWN and never a skew), and carries the transmit
  timestamp of the request (bytes 40..47) in its originate timestamp (bytes 24..31, the offsets of RFC 4330 figure 1), so
  a reply to another query is never read as the clock of the controller.
  It prints every port as open, closed or timeout, the clock skew of the controller in seconds, and FAIL when the clock is
  more than 300 s off (the Kerberos default), with the step to sync the clocks; a controller whose time cannot be read (a
  timeout, a network error, or a reply that is not accepted) is UNKNOWN. A controller whose LDAP
  port 389 or Kerberos port 88 is not open (closed or timed out) is a FAIL as well, and that FAIL wins over the UNKNOWN of
  a clock that cannot be read; the SSH port 22 is still only reported, because the setup script installs SSH later. The run
  then exits 1 (0 when every controller passed); without the flag nothing changes and nothing is contacted. The probes run in
  the same run as the list of controllers, before the owner has read it, so the owner runs the tool without `--preflight`
  first, checks the list against their own controllers, and only then runs it again with the flag. That second run reads DNS
  again: the first list does not limit what the second run probes, and the addresses it probes are the ones that run prints;
  nothing is pinned, so the second run trusts DNS as much as the first one did. Limits: the preflight reaches
  only the addresses DNS gave and only the first address of each controller, and it cannot read the clock of a controller
  that has no address at all. **Covered by tests only, unmeasured on a lab DC:** the tests use fake sockets and a fixed
  clock, so no controller was contacted.
- `scripts/newton-ad-discover`: give it a domain and it finds the domain controllers and the PDC emulator from DNS
  (SRV `_ldap._tcp.dc._msdcs.<domain>` and `_ldap._tcp.pdc._msdcs.<domain>`, then A and AAAA) and prints the read
  inventory entries and the `newton-ad-setup windows|samba` command for each DC; with `--write --ops-pubkey FILE --ou ...` it also
  prints the `newton-ad-setup write` commands, PDC first, every other DC with `--domain-device`; the write commands
  carry the operations key and never the audit key, and the same key given twice is refused. It only prints: no
  credentials, nothing is run. DNS answers are untrusted: host names must be plain letters, digits and hyphens inside
  the domain (at most 253 characters), at most 32 DCs are used, anything else is skipped with a printed reason, an
  address with a scope id is dropped with a printed reason (the tool never connects to it), every
  value is shell-quoted, and the output tells the owner to check the list against their DCs. The work one host can cost
  is bounded: at most 64 A and AAAA records are read for it and at most 8 scope-id refusals are printed for it, and what
  was cut is said out loud. Limits: tested with a fake
  resolver only, not against a real Windows or Samba DNS server; it cannot see a DC whose records are missing from DNS;
  without a PDC record it withholds the write commands (exit 6). New dependency: `dnspython` (ISC licence), used only by
  this tool.
- `newton-ad-discover --fetch-host-keys`: the tool also asks `ssh-keyscan` for the host keys of every domain controller
  it found and prints, for every key, its SHA256 fingerprint (the way `ssh-keygen -lf` prints it) and the ready
  `known_hosts` line, so the owner does not have to pin the host keys by hand. The scan is one per controller
  (`ssh-keyscan -T 5 -t ed25519,ecdsa,rsa -p 22 <host>`), run with an argument list, never through a shell, and with a
  timeout; a controller whose scan fails, or that has no key, gets a plain line and keeps the placeholder `known_hosts`
  line. A scan travels over the network, so it can be spoofed: the tool says so and tells the owner to compare every
  fingerprint with the one the controller shows at its console before trusting it. When a controller has more valid host
  keys than the cap of 8, the tool says the list was cut, so the owner knows the fingerprints and the
  ready `known_hosts` lines shown are not all of them.
  `--resolver` is for the lookups of the discovery only: `ssh-keyscan` resolves the host name of a scan with the system
  resolver, so the scan can land on another address than the one DNS gave, which is one more reason to compare every
  fingerprint at the controller. Nothing is written, and without the flag the tool behaves exactly as before. Limits:
  tested with a fake scan only, never against a real domain controller.
- Four DNS checks in the Active Directory audit (52 in all), read-only, on Windows and Samba: AD-A-68a a primary
  zone allows non-secure dynamic updates (high); AD-A-68b a zone that takes dynamic updates has aging off (low);
  AD-A-69a a domain controller has no `_ldap._tcp.<domain>` SRV record (medium); AD-A-69b that SRV record names a host
  that is not a domain controller (medium). They read the `dnsZone` and `dnsNode` objects of the DomainDnsZones
  partition and the domain controller computer objects through three new queries, with the rights the read account
  already has; the constants and encodings come from MS-DNSP (design note `docs/proposals/ad/DESIGN-dns-helpers.md`
  lists each with its section). **Covered by tests only, unmeasured on a lab DC:** the fixtures are built from the
  spec's encodings, not read from a DC, and whether the ordinary audit account can read these DNS objects is not
  confirmed (if it cannot, the checks say UNKNOWN, never PASS). Limits: only the domain's own DomainDnsZones partition is
  read (not ForestDnsZones, `_msdcs` zones or the legacy container); the aging check does not read the server-level
  scavenging setting; a DNS name with a label that is not ASCII is refused, though the spec allows such a label, so
  the check says UNKNOWN instead of reading the name; zone transfers and forwarders are NOT checked, because MS-DNSP
  stores neither in the zone object and reading them needs more rights than the read account has. The query set changed,
  so its hash changed: run the printed setup script again on each DC to install the new `queries.json`; until then the
  audit refuses the older collector's document as out of date.
  A DNS base the audit account may not read is reported as access denied (ACCESS_DENIED), like every other denied read.
- `newton_plan_ad_forward`: plans the OpenWrt change that forwards an Active Directory DNS domain to its domain
  controllers (dnsmasq conditional forwarding). Give the domain and 1 to 8 private DC addresses; Newton reads
  `uci show dhcp` and builds one `add_list dhcp.@dnsmasq[0].server='/<domain>/<dc>'` per controller, plus
  `add_list dhcp.@dnsmasq[0].rebind_domain='/<domain>/'` when rebind protection is not off (OpenWrt's default is on,
  and it drops private-range answers). Lines already on the router are not added again (all present: `no_change`,
  nothing staged); nothing is removed. An entry the router already holds is matched by the address it names
  (`fd00:0:0:0:0:0:0:1` is `fd00::1` and `::ffff:192.0.2.10` is `192.0.2.10`, so the same address is never added
  twice; a scoped text such as `fd00::1%br-lan` is compared as text, so it is never proof that the
  address without the scope is there). A domain the router marks local-only (dnsmasq's `server=/<domain>/` with no address, or its
  `local=/<domain>/`) is planned normally: a forward for the same domain wins over that entry, so the
  plan says in a note that the router marks the domain local-only and that the forward overrides it. An `address`
  entry for the domain itself that carries an address (`address=/<domain>/<ip>`, `address=/<domain>/#`, or the same
  with `/.<domain>/`, `/<domain>./` or `/*.<domain>/`) is refused and nothing is staged: dnsmasq answers A and AAAA lookups itself, and the owner removes
  that entry through `newton_plan_change` first; a local-only `/*.<domain>/` entry is refused too. An `address` entry, a local-only entry, or a
  `server` entry to another address, for a name
  below the domain does not stop the forward of the domain but keeps those names from reaching the domain
  controllers, which the plan says in one note. `ad_forward.notes` is Newton's own wording; the router's other entries
  for the domain come back as device data in `ad_forward.existing_servers`. It uses the normal plan, approval, apply and
  undo path with the device-side rollback; a no-install router gets an owner script, as for any list change. Measured
  with dnsmasq 2.91 on Linux, not on a router. With it the tool count is 25; the three build tools of this release make 28.
- `newton-doctor ad`: a read-only check of the Active Directory entries of the inventory, run as the `newton` account
  (`sudo -u newton /usr/local/bin/newton-doctor ad`). It reads local files only and contacts no DC. It reports a write
  entry whose `ad_domain` names no write entry of the inventory, a domain with two domain devices, a DC that has an audit
  entry but no write entry (only where it can tell: an inventory that does not load may hold that write entry, so then
  the doctor says it cannot be judged until the inventory loads), a `key_file` that is a placeholder, missing, or not
  owned by `newton` and 0600, a `known_hosts` that is a placeholder, missing, not owned by `newton` or writable by group
  or others, a pinned `known_hosts` with no key for the host, and a domain device with no recorded approval fingerprint,
  each with the command that fixes it. An inventory Newton itself refuses to load is a finding too: the check asks
  Newton's own inventory loader, so a refusal (a device name or a platform it does not accept, an AD entry without a
  valid host, user or port, a bad `auth`, `profile` or `proxy_command`, a `key_file` or `known_hosts` that is not a path,
  an entry of another platform without a `known_hosts` file) is named in the loader's own words: Newton loads no device
  from that inventory, so the run exits 1. Every value of the inventory is untrusted text: a value reaches a
  printed command only when it passes the grammar the inventory loader uses for that field and cannot look like an
  option, and the command quotes it; otherwise the next step is the one fixed line that edits the entry. Exit codes as
  the rest of the doctor: 0 clean, 1 a finding, 3 something could not be judged, 2 wrong arguments or account. Nothing
  records the fingerprint each DC printed, so it shows the recorded one for the owner to compare.

### Fixed
- `newton-doctor ad` asks the inventory loader Newton itself uses whether the inventory loads, instead of deciding
  with a copy of its rules. An inventory Newton refuses is now a finding (Newton loads no device from it), so such a
  run exits 1 instead of a run of PASS lines, and the doctor's own scan of the entries still names every entry it finds
  wrong, because the loader stops at the first one. An error the loader did not expect is INCONCLUSIVE, never a PASS.
  While the inventory does not load, the doctor claims nothing about a pairing: it does not say that a domain has audit
  entries only, nor that a write entry has no audit entry, but that the pairing cannot be judged until the inventory
  loads. An `ad_domain` that names an entry of the file that Newton does not load now says so, instead of saying that
  the inventory does not hold the entry.
- `newton-doctor ad` pairs a DC's audit entry and write entry by a normalised host (lowercase, one trailing dot
  removed), so a host that differs only in case or ends in a dot no longer reads as a missing write entry. When one
  entry gives an IP address and the other a name, the doctor resolves no name, so the pairing cannot be confirmed: it
  says so as INCONCLUSIVE (the run exits 3) instead of calling the write entry missing. It names no write entry as the
  partner of the audit entry: it lists the write entries of the domain whose address is of the other kind (IP versus
  name), and says the owner must use the same host text in both entries of a DC. A write entry that is unpaired for
  another reason keeps its own note. A DC that really has no write entry is still a finding, but only where the doctor
  can tell: an inventory that holds an entry Newton does not load may hide that write entry.
  The IP-versus-name test looks at every write entry of the domain, paired or not. The setup command of a missing
  write entry never names a device already in the file: the next step is then `sudoedit`. While the inventory does not
  load, or could not be judged, the doctor makes no pairing claim.

## [1.4.2] - 2026-11-24

### Fixed
- AD setups, Windows: the 1.3 audit setup and the 1.4 write setup no longer strip each other's read of the shared
  install root `C:\ProgramData\Newton\ad`. Each re-protected the folder for its own account only, so whichever ran second
  broke the other: after the audit setup and then the write setup the audit login always answered "the install is not
  safe" (measured on a Server 2025 controller on 2026-11-24), and the reverse order makes the write helper refuse its
  install. Each setup now also gives the other Newton account a read of the root folder only, when that account exists.
  Run the printed setup scripts again on each controller that has both. **Covered by tests only.**
- AD collector, Windows: a search root the audit account may not read is reported as access denied and not as an error.
  ADSI answers 0x8007200A ("the specified directory service attribute or value does not exist") when it cannot read the
  search root itself, which is what the `CN=Password Settings Container` base answers to the ordinary audit account
  (measured on a Server 2025 controller on 2026-11-24: the password settings query fails with that error, a control search
  of `CN=Users` reads six rows, and the Administrator reads both).
  The collector mapped that error to `error`/`other`, so the audit reported AD-A-35 as UNKNOWN with the reason ERROR. The collector now maps it to `denied`/`access_denied` where the search starts,
  and only there: the same error raised while a row that came back is read keeps the mapping it had. The audit turns
  `denied` into ACCESS_DENIED, as it did for every other denied read before. The query set did not change, so its hash
  did not change and the audit does not refuse the document; the collector's bytes did change, so run the printed setup
  script again on each controller to install the new collector. **Covered by tests only:** the mapping is exercised in
  PowerShell against a fake searcher that raises the COM error, once where the search starts and once where a row is read.

## [1.4.1] - 2026-11-22

### Fixed
- `owrt-change.sh`: a change to named nft objects whose rollback the apply run could not follow (the link was lost,
  the run was interrupted or killed) no longer leaves the live firewall holding the change with nothing said. The apply
  records that a firewall restart is owed; the unreachable ALERT, the INTERRUPTED line and `status` say so and name
  `abort`, and `abort` restarts the firewall once the change is rolled back (it says so when that restart fails).
- `owrt-change.sh confirm`: a confirm the router refuses because an overlapping confirm already took now reads the
  router's status and says the change is confirmed, instead of saying the router rolls it back.
- `owrt-change.sh plan`: a staged-diff read that fails now discards the staged session (or names the abort to run)
  and leaves no plan record, instead of ending "cannot read staged diff" with the session still open.
- `owrt-change.sh abort` of a session id this host never planned (no plan record, no STAGED line) now fails and says
  to check the id, instead of exiting 0 as an abort of a change that was only staged.
- `owrt-change.sh status` of a change confirmed from this host that the router no longer remembers (after a reboot
  or a later confirm) adds a NOTE that the change stays live.
- `owrt-change.sh`: on an installed Newton the setup hints (upgrade, profile, approval key) name
  `sudo -u newton /usr/local/bin/newton-router-setup`, since the bare name is refused there.
- `owrt-safe-apply.sh apply`: when the deadline record cannot be written, the helper rolls the change back and fails
  instead of printing APPLIED for a change its own `status` and `abort` would then treat as only staged.
- `upgrade` also replaces the guard and its init when the guard status is `restored ...` (no change in flight), and
  when a failed guard keeps the old files while this Newton ships different ones it stops with the guard status and
  the `newton-guard recover` step instead of printing DONE (every later change then refused the router and named
  `upgrade` again).
- `upgrade` on a router whose guard reports no status (it cannot run) now says so and names the install run for that device
  (`sudo -u newton /usr/local/bin/newton-router-setup <device> install`), instead of a `newton-guard recover` step
  that cannot run there. It still stops; every other guard status keeps its message.
- `install`, `upgrade` and `uninstall` read only the first line of the guard status: a `/etc/config` entry the guard
  cannot name adds a `skipped ...` line, which made `uninstall` refuse and `install` fail step 4 with no reason.
- The setup tool's admin login failure names a changed or unknown router host key, the known_hosts file that pins it
  and the `ssh-keygen -R` step, instead of the password or plain-key advice.
- An unknown device names the inventory file, the devices it names and the table to add (setup tool and MCP server).
- The leftover rpcd undo-file message (no-install backup, owner script, setup tool) says the live settings may hold
  the unconfirmed change and how to copy the settings from before it back, before it says how to clear the folder.
- The owner script prints its applying line after its precondition checks, so a router that changed since the plan
  stops the run with the approval restored, as the setup tool already assumed.
- The install disclosure says what the WAN-health check costs in data on each listed WAN, and that the copies of
  your settings `uninstall` keeps are dropped by the next firmware upgrade.
- A config file that appeared in `/etc/config` during a change window (a package install, a LuCI add, or the defaults
  of a firmware upgrade) and was moved to `/etc/newton/quarantine/<session>/` by the guard's restore is no longer
  deleted later: the guard prunes only its own `recover-*` directories, and a restore's directory stays until you
  remove it. The restore logs a warning naming it, the router's `status` line ends `quarantined=<n>`, and the apply,
  abort and status output tell you where the files went.
- `newton_plan_tier` lists in `controls_without_probe` the controls of the batch that seal no control probe (OW-FW-01,
  OW-FW-04 and OW-FW-09 take a `{placeholder}`, so no probe is matched for them), with a note that only the built-in
  steps check them after the apply.
- The router program's grammar table names the program's `hello` version (1.3.3) and abort's exit 3 (`not-owner`,
  `already-confirmed`); tests now check the table's stdout and exit columns against the program.
- `newton_grant_off` answers for a no-install router too: a grant covers no-install plans, and the owner can now
  ask the agent to end it there; the no-install tool list names it.
- An nmap scan result is bounded: it carries at most 500 open ports (findings, report update and envelope alike),
  with the full `host_count` and `port_count`, `truncated` and `returned_port_count`, and a note when it was cut. The
  envelope keeps addresses and port numbers only; the service names are in the findings. A wide-open /24 quick scan
  went from about 7 MB to about 120 KB.
- A host whose nmap port list is too long to read (a full-tcp scan of a wide-open host) no longer vanishes from an
  `ok` scan: the scan is `incomplete` and `too_long` names the host.
- A no-install apply that rpcd answers with "nothing staged" is `not_applied`: the approval goes back to the owner and
  no `unknown` receipt is written.
- A plan or status that times out says the router may not be answering and to check it with `newton_read uptime`
  before planning or asking again.
- Each tool call's line in `mcp-audit.log` ends with `dur_ms=` (how long the call took) and `bytes=` (the size of its
  result as JSON), so the owner can see what a session cost.
- The off-device backup copy, the change receipt and a rewritten plan record are synced to disk before and after
  their rename, so a crash right after a change cannot leave them empty and make `newton_plan_undo` refuse.
- AD writes: an `unavailable` or `denied` from the DC write helper's own install check (it refuses before it reads the
  request; both helpers now mark that answer `"stage":"install"`) is `refused` with the step "run the DC's write setup
  again, then apply the same plan", instead of `apply_unknown` with "do not apply the plan again". The status and the
  abort name that write setup step when the helper answers either code.
- AD writes: `newton_ad_change_status` of a change the DC holds `refused` gives the reason the apply's receipt kept;
  a `not_found` after a lost apply (receipt `apply_unknown`) no longer says the plan can be applied (Newton refuses a
  second apply), and for a new user whose password left the plan it says to plan the user again. The abort of a
  change the DC holds no record of, or answers with an error, now says what that means.
- AD writes: the `denied` step names the write account's delegation and the write setup; a refused or conflicting
  `user-create` says its next plan has a new password and the one shown is never set; an `unavailable` user-create
  keeps the write setup step; a retry of a user-create the DC answered `conflict` is refused as spent, never "may
  already be written".
- AD writes: a target name outside the sAMAccountName pattern is refused with the pattern (lowercase, 1 to 20
  characters) in the refusal, the `newton_ad_plan_change` description and SKILL.md.
- `newton-ad-setup` with its options before `write` or `approval-key` says those words come first, instead of
  "invalid choice: 'write'".
- Samba write helper: a sweep pass whose bind fails stops binding for that pass (one bind per pass, not one per stuck
  record), and a pass that leaves an expired change armed answers `error`, so `newton-ad-sweep.service` reads failed.
- A serial `push` whose line drops while it sends the file's end line now says the target was already overwritten
  and names the backup. The write can fail after its bytes reached the router, so it used to say the file was not
  written when the router may already have written it.
- A serial `push` stopped, or whose line drops, before the file's end line is sent says the target was not written:
  the router shell runs the `cat >` redirect only once it has read the whole file, and a Ctrl-C abandons it. It used
  to say the target was already overwritten from the `cat >` line on. After a dropped line it also says to press
  Ctrl-C on the console first, since a Ctrl-D at the router's `>` prompt would write the part sent.
- A serial line that drops (a USB-serial adapter pulled out) while a `push` checks for or makes its backup, or while
  it checks the written file, gives one line and exit 7 that say whether the target was written; during `run`,
  `read`, `send`, `probe` or `login` it gives one line and exit 3. Each used to end in a Python traceback.
- A serial `push` of a file that is not UTF-8 text, and a `--password-file` or `--secret-file` that is not UTF-8,
  are refused with one line and exit 2 instead of a traceback.
- The serial tool prints at most the last 64 KB of console text and says on stderr how much it left out and which
  transcript holds it all; `read --seconds` and `send --wait` must be between 0 and 600. A flooding console used to
  print everything it captured, with no bound on how long.
- `scripts/newton-lab-isolation --from-file` on a capture file with no packets (empty, or only tcpdump's banner and
  summary lines) is INCONCLUSIVE with exit 3 instead of a PASS, and `--from-file` no longer needs `--iface`; an
  unreadable line in a file asks whether the capture was taken on an Ethernet interface with `-e` instead of naming
  `--iface`.
- `newton-rules add` and `remove` copy `rules.toml` to `rules.toml.bak` (mode 0600; `rules.toml.bak-<time>` when that
  exists, never through a symlink) before a rewrite that drops a comment, and the note names the copy; when no copy
  can be made the rewrite is refused and the file is left as it was. The comment used to be gone with only a note.
- The lab runner refuses a lab file whose `[settle]` `timeout_s` or `poll_s` is not a finite number above zero, or
  whose `quiet_s` is not a finite number of zero or more, naming the key; `timeout_s = inf` polled over ssh forever
  and `poll_s = 0` busy-looped.
- The approval dialog's "no TOTP approval key on record" names `newton-enrol totp <device>` (and
  `newton-enrol level <device> passphrase`) instead of `approval-key`, which never writes a TOTP record.
- A HIGH-risk plan's authenticator code is spent only after the second confirmation, so a mistyped confirmation no
  longer turns the retry with the same code into a replay counted toward the lockout.
- On an installed Newton the next steps of the approval dialog, `newton-enrol`, the scan consent refusal, the
  no-install refusal, the client-checks repair message and the owner-finish advice name the `sudo -u newton
  /usr/local/bin/...` form, which the installed launchers accept.
- `newton-approve ad-change` on the id of a router plan or a scan request names the command without `ad-change`.
- `newton-enrol rotate`, `totp` and `level ... totp` refuse an Active Directory entry (AD approvals ask for the
  passphrase only; rotate names the AD route instead of running the router setup against a DC). In a source checkout
  `rotate` runs the source tree's `newton-router-setup`; a missing setup tool names NEWTON_HOME instead of the missing
  path, and a failed rotation says the router may already hold the new key.
- A first install run again after its bootstrap step failed prints the first-install steps (the credential moves and
  the MCP client command) instead of "Newton updated successfully.".
- The refusal for a leftover `/opt/newton.old` says to remove the unfinished `/opt/newton` first and restore with
  `mv -T`: a plain `mv` moved the backup inside the partial tree, and the next run deleted it.
- The update steps say when the installed `newton-bootstrap` differs from the release's and give its `self-update`
  command; the owner docs say a bootstrap installed by an earlier release asks for a 12-hex prefix of the id.
- The launchers run from a root shell (`SUDO_USER=root`) say to run them from the owner's own account; SETUP.md step 4
  says to leave the root shell.
- The managed-settings advice for a file that is not valid JSON says to copy it aside and fix it, and to replace the
  whole content only when none of its other settings are needed; valid JSON that is not an object gets the whole
  object, and a key that is not `true` gets "change its value", so the one-line advice is given only for a JSON object
  without the key.
- `newton-doctor --device` quotes the setup check's "restricted-key proofs skipped" line and names `swap-key` or
  `add-key`, instead of blaming the setup tool's version.
- Owner docs: the hold window is the plan's timeout minus 15 s; the release README ticks only Claude Code as tested;
  docs/SETUP-CLIENTS.md no longer lists Claude Desktop among the clients; SKILL.md names `not_found` among the AD
  change states; SECURITY.md names the WAN-health, scan and rules scripts in scope; SKILL.md has a size cap test, and its
  broadest triggers are scoped to a network Newton manages.

## [1.4.0] - 2026-11-21

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
  DC does not catch up its result says what the undo restored and which attributes it left as conflicts, or
  `abort_failed` when Newton does not know whether that abort ran (an abort the DC answers with `conflict` because its
  own undo already ran is reported `not_tested` with that undo's `dc_state`). A confirm the DC answers with an error
  or a conflict after every DC showed the change is `not_confirmed`, and Newton reads
  the DC's record (an unlock has no undo, so for an unlock the result says it stays written and never what the record
  reads: the DC normally records an unlock `confirmed` when it is written, and a DC that cannot write that record keeps it armed;
  a conflict says the PDC emulator may have read the account locked again, or could not read the account or its record). The result says the change is still armed only when that record says `armed`; when the record
  shows its undo already ran (its `undo_at` passed, or an abort ran it) it carries that undo's `dc_state`, and when
  the record cannot be read it says Newton does not know whether the confirm was recorded; a record that says `confirmed` (the DC recorded the confirm before its
  error) makes the result `confirmed`, and a Samba DC answers such a confirm ok. A
  second apply of a plan whose earlier apply reached the DC, or may have (its receipt says anything but `refused`,
  or the password of a new user already went out), is refused before it is sent: `replay` with code `not_sent`, and
  the earlier receipt is kept; a replay the DC itself answers is `replay` too, changes nothing and keeps the earlier
  apply's receipt; a pending receipt is an earlier apply that may have reached the DC until the DC's record of the
  transaction answers `not_found` (the status then says no apply of the plan had reached the DC's write when it was
  read, unless an apply sent before Newton stopped is still on its way, and a retry sends the plan); a second apply of a
  plan while one runs on the same host is refused `not_sent` before anything is sent or written. If the connection to a domain controller fails mid-apply, the receipt (a final receipt that cannot be
  written is named in `receipt_error` and never changes the result; before it sends the apply, Newton writes a pending
  receipt (`apply_unknown`) and syncs it to the disk; when that receipt cannot be written, nothing is sent and the
  apply is refused with code `not_sent`; a receipt whose presence cannot be checked is taken for an earlier apply)
  is still written and the result names the lost step (`apply_unknown`, `confirm_unknown` or `abort_failed`) and
  sends the owner to `newton_ad_change_status`; a change that is not confirmed is put back by the DC itself at or after
  its `undo_at`, when it next runs the undo (a Samba DC whose write setup was run with this release runs a sweep timer about once a minute
  that retries an undo whose run did not finish or that a reboot dropped (an `undo_failed` record is final); a Windows DC retries one at the next Newton request to
  it), except an unlock, which has no undo and stays written, and a new user whose objectGUID the DC did not record
  (the connection can fail between the add and that record), which the DC leaves in place and records `undo_failed`
  with its DN in `conflicts`; after a lost apply the DC may already have run the undo, when it could not finish the
  apply after its write: its record then says `undone` or `undo_failed`. A connection lost while a DC is read back counts
  as that DC not showing the change, so the change is aborted, except an unlock, which is not aborted and reaches the other DCs by replication. An apply request the SSH runner refuses before it
  leaves the Newton host is recorded as refused with code `not_sent`: nothing was sent, and the plan keeps its
  password, so it can be applied again once the cause is fixed (the transport's own size refusal, which the apply's
  contract check makes unreachable today, is refused before send too and keeps the code `schema`); a confirm, an automatic
  abort, an abort or a status the SSH runner refuses the same way carries the code `not_sent`: a status says it was not
  sent and could not be read, and a confirm or an abort says it was not sent and the DC holds the change as it did: a
  change still armed is put back by the DC itself at or after its `undo_at` (an unlock stays written). A domain controller that answers the apply with an
  error code that can follow a write it tried (`error`, `denied`, `not_found`) or any other error (except the codes both
  helpers give only before they write, which are `refused` only when the DC holds no record of the transaction and
  the answer carries no `unmarked`, or its record says `refused`) is no longer reported
  as `refused` unless its own record of the change says `refused`; otherwise the result is `apply_unknown` and sends
  the owner to `newton_ad_change_status`. Both helpers look for a record of the transaction before the token and the approval window, so a
  retry of an apply the DC holds whose receipt is gone from the Newton host answers `replay`, never `bad_token` or `expired`; against a helper set up with an earlier release, which
  checks the token first, Newton reads the record by txid and the retry is `apply_unknown`, never `refused`. When the DC reads the target again after such an error and finds neither
  the before-image nor the after-image, somebody else changed it and Newton's write may have landed first: the result
  is `apply_unknown` with the `live` value the DC read, never `refused`, and the DC records the change `undo_failed`
  so that its undo never writes over the other change (an unlock stays armed). A value the re-read cannot read (a
  move's parent, the domain head, an account's `userAccountControl`) is a target that cannot be read, so the record
  stays armed. After an error code the DC answered itself, its atomic write wrote nothing, so a re-read that shows
  the after-image is somebody else's same change: the result is `conflict`, the DC records it `refused` and its undo
  never runs over that change. The DC marks the record before it reads the target again, so while that mark (or the
  refused record) is on its disk no later undo of it (the timer or task, the sweep, an abort) writes anything; the undo
  is cancelled even when the refused record cannot be written, and the answer is then an error (`apply_unknown`), never
  `conflict`. A DC whose store takes neither the mark nor the refused record (a full disk, say) leaves the record armed
  with no mark, which its undo cannot tell from a write whose answer was lost: the answer then carries `unmarked`, and
  Newton reports `apply_unknown` and tells the owner that the DC's undo may write the before-image over somebody else's
  change (a known limit: nothing on that DC's disk can stop it). A failure inside the handling of a
  write that was sent leaves the record armed, never `refused`. A Samba record is created `refused` and reads `armed`
  only once its undo timer is armed, right before the write (a refusal before the write, or a timer that cannot be
  armed, leaves it `refused`); on Windows, a task that cannot be registered whose refused record cannot be written
  answers `unavailable` with `unmarked`, and the current record is the highest generation that can be read and parses; a
  generation that cannot be read stops the reader, so a generation whose write failed after its file was made (a full
  disk) never hides the record below it. On both DCs a record that cannot be read is never taken for absent: a read of
  it that raises (a sharing violation, a denied access, an IO error) makes a status, a confirm, an abort and the timer
  or task answer `error` and write nothing, and the sweep leaves that transaction for a later pass; a Windows store that
  cannot be listed is never taken for empty either (the apply answers `error` too). On both DCs a record write that fails is read back, and the helper acts on
  what the disk holds (the write can fail after the record reached the disk, when its flush fails; a read-back that fails counts as the armed record having landed): an armed record
  of a write that was never sent that cannot be written `refused` again answers with `unmarked`, and a `conflict`
  never carries `unmarked`. On Samba a refusal after the undo timer was armed cancels the timer, and when its refused
  record cannot be written it answers with `unmarked`, and with `error` in place of `conflict` (a move whose rename
  the server answered with "no such object" is such a refusal); Newton never reports an answer that carries
  `unmarked` as nothing changed unless its record of the change reads `refused` when Newton reads it back (a replay
  the DC answers stays a replay). The undo of a new user looks the account up again by the GUID it was created with, so
  an account somebody renamed is `undo_failed` (still there), never `undone`; a new user with no recorded GUID is
  never `undone` from a lookup by its name: it is left in place and recorded `undo_failed` with its planned DN as the
  conflict. A new user whose undo facts are missing right after the add is put back at once, and only by its
  objectGUID: with the GUID read, the object of that GUID is deleted wherever it is; with no GUID nothing is deleted
  (an account at the planned DN may not be Newton's) and the record is `undo_failed` with the DN. Every delete,
  modify and rename the helpers send, in an apply or an undo, names its object by the GUID form of its DN
  (`<GUID=...>`), never by a DN a search answered earlier (the machine account quota on Samba is written on the domain
  head by its DN), so a write never lands on an account somebody made at
  that DN after moving Newton's away, apart from the three DN values named in the known limits (this form was not
  run live on the lab DCs; tests cover it). The Samba undo of an
  attribute or a membership reads the live value, or the group's members, by that GUID too, never by the DN that
  search answered, so it never records `undone` from an object somebody made at that DN. Samba decides whether a
  member is in a group in one search of the group by its GUID, matching each member value by the GUID the directory
  gives with it (the extended DN control); Windows decides it in base searches of the group named by its GUID with
  the member named by its GUID in the filter. A member moved between two reads, even moved back, never reads as
  out of the group (in the apply's checks, the confirm, the undo and its re-read). The helpers bind as the domain
  controller's account, so the directory's ACLs apply, and an attribute it cannot read looks like one that is not
  there. A group that shows no member value (empty, or a member list it cannot read) is never taken for "the member
  is out": the undo of a membership then writes, and the domain controller checks the write against the values it
  holds; the read-back and the confirm of a member-add read it as a target that cannot be read. A missing machine
  account quota, a missing lockoutTime and a missing encryption-types value (unless removing it is the change) are
  read the same way, never as 0 or as "no value": the record then stays armed rather than reading `undone` or
  `confirmed`. The read Newton verifies every domain controller with answers that image too (`outcome`, beside the
  planning image `live`): each domain controller binds as its own account, so one that still holds another value it
  cannot read never shows the after-image (a removal's aside, see the known limits), and the change is aborted
  rather than confirmed. Newton refuses to plan a
  change whose before-image the account cannot read (a quota, a userAccountControl, a moved object's parent). A new
  user counts as gone only when a base search of its GUID name answers noSuchObject, never from a
  search on objectGUID that finds nothing (an objectGUID the account cannot read matches no filter); one that answers
  no entry is a user the account cannot read, never gone. On Windows a member reads out of a group only when a second
  pair of searches agrees with the first. Both helpers refuse
  an apply with `conflict` (with `live` and `armed`, which Newton explains) while another armed record names the
  same target: that record's undo could write the before-image over this change once it is confirmed (a write that
  got no answer stays armed on its before-image). Nothing is armed or written; a store that cannot be checked
  answers `error`. The check reads only the store of the domain controller it runs on (see the known limits for a PDC role move). A user-create whose plan record cannot be rewritten without its password after the apply sent it
  keeps the password there, and the result says so in `secret_error`. A malformed record never stops the sweep of a
  domain controller: it is skipped and left as it is.
  On both domain controller helpers an unlock is never undone. An unlock whose write succeeded is recorded
  `confirmed` (on Samba, a read-back that fails after it reads the account again first; on Windows, a confirmed record
  that cannot be written leaves the unlock armed, and its status says an unlock has no undo). One whose write failed for a
  reason other than a conflict is read again: `confirmed` when the account shows the after-image and the DC gave the
  write no error code of its own (an after-image after the DC's own error code is somebody else's same change:
  recorded `refused` with the conflict and answered `conflict`), `refused` when it
  still shows the before-image and the DC answered the write with its own error code; any other value is somebody
  else's change, recorded `refused` and answered `conflict` when the DC answered the write with its own error code,
  and otherwise left armed, since the unlock may have landed before that change. An account that cannot be read
  again, a write the DC gave no answer to, or a record that cannot be written leaves the record armed (a Samba DC's sweep
  reads the account again for an hour after its `undo_at` and records it `confirmed` only from the after-image, never
  `refused` from the before-image: its write may still land), and the status of an armed unlock says it has no undo. An unlock write the DC refused as a conflict is recorded `refused` without a
  read. Neither the sweep nor an abort writes the lockout back, and the abort of an unlock is refused on both helpers.
  `newton_ad_abort_change` works only on a change still armed (an apply cut off before its confirm). Once confirmed,
  Newton does not undo it (a known limit: if the PDC role moves while an earlier change of the same target is still armed on the old PDC, that domain controller's undo can write the earlier before-image over the new change): the owner plans the reverse change. An unlock has no undo and is written at once. The owner approves each change in their own terminal with
  `sudo -u newton /usr/local/bin/newton-approve ad-change <plan_id>`; the
  domain controller checks that approval itself and arms its undo before it writes, and Newton confirms a change only
  when every domain controller with a write entry in the inventory shows it. Newton does not list the DCs of the
  directory, so a DC without a write entry is never read; each plan lists the DCs it will check and says so. `scripts/newton-ad-setup write windows|samba` sets up the `newton-ops`
  account, which is never in a privileged group and holds only the rights these changes need; the Samba setup checks
  its sudoers line with visudo before it installs anything. The write helpers were
  tested live in the lab on Windows Server 2025 and Samba 4.22 domain controllers; both changed after those runs
  (the failed-write, unlock and confirm outcomes above, the replay checked before the token, and the Samba sweep
  timer), and those changes are covered by
  tests only. The second-DC setup
  (--domain-device), the printed ad_domain_guid and changes on a domain with two domain controllers were tested live
  on a two-DC Windows Server 2025 domain and a two-DC Samba domain: both DCs of a domain hold the same approval key,
  every change is confirmed on both, and a withheld confirm rolls back on both; the log of those runs is not kept in
  this repository. A move of the PDC role between domain controllers was not tested live.
- `SKILL.md` has an Active Directory section: the setup, the audit, the change flow and what Newton does not change.
- An installed Newton has a new launcher, `/usr/local/bin/newton-ad-setup`, with its own sudoers rule (no
  `NOPASSWD`, `timestamp_timeout=0`): `sudo -u newton /usr/local/bin/newton-ad-setup approval-key <device>` records
  the AD approval fingerprint in the newton user's state directory, where `newton-approve` reads it. It takes
  `approval-key` and one device name, nothing else. The `newton-approve` launcher takes `ad-change <plan_id>` as well
  as a lone plan id, and `newton-doctor` checks the new launcher like the others.
- An apply that holds: `newton_apply_change` with `hold=true` (`owrt-change.sh apply ... --hold`) runs the verify
  rounds and does not confirm, so a change that can only be tested from a client stays under the router's rollback
  until `confirm_by`; `newton_confirm_change` (`owrt-change.sh confirm`) confirms it after one more verify round, and
  `newton_abort_change` rolls it back. Without `hold` the apply confirms on its own as before. Installed OpenWrt
  routers only, and not for a change to named nft objects or a plan with client checks. A held apply writes a
  receipt with outcome unknown; the confirm adds a confirmed one.

### Known limits
- A new user's objectGUID is read on Samba at its planned DN, and on Windows by its sAMAccountName right after the add:
  an account somebody else put at that DN, or gave that name, in that moment (after moving or renaming Newton's away)
  would be taken for Newton's.
- A write names its object by GUID, but three names in it are still DNs read just before: the member value of a
  membership change, the new parent of a move, and the parent of a new user. A member or an OU somebody moves away
  and replaces at that DN in that moment would be the one written; for a membership, the undo of that membership,
  which matches the member by GUID, then reads Newton's account as not changed by the apply and records undone while
  the other account stays in the group. The undo of a new user and of a move checks the
  object (disabled, unchanged, no members; still in the parent the apply put it in) and then writes it in a second
  request: a change somebody makes to that object in between is not seen.
- An empty group and a group whose member list the helper's account cannot read look the same, and so do a missing
  value and one it cannot read. A member-remove and an encryption-types change that removes the value take "no
  value" for their after-image: if somebody makes the member list or the value unreadable to the domain controller's
  account after the apply read it, their read-back, their confirm and the read that verifies each domain controller
  read "removed" whatever is there (a member or a value put back while it is unreadable included). A read cannot
  tell them apart: removing a group's last member leaves the same answer. The undo of a new
  user reads its groups the same way: a membership the account cannot read is not seen, and the delete goes ahead.
- A new user counts as gone when a base search of its GUID name answers noSuchObject. Samba resolves that name as the
  system, whatever the account may read (its source); whether a Windows domain controller does so for an object
  whose objectGUID the account cannot read was not measured. An object the account cannot see at all (a denied list
  right on its parent) answers noSuchObject as well (Samba's acl_read; on Windows not measured): such a user would be
  taken for gone, and the record would say `undone` while it is there.
- On Windows a member is in or out of a group by four separate searches; a right on `member` that changes more than
  once inside those searches can still read the member out while it is in.
- The same-target guard reads only the store of the domain controller it runs on. If the PDC role moves to another
  domain controller with a write entry while an earlier change of the same target is still armed on the old PDC
  (a write that got no answer, or a lost confirm), a change applied on the new PDC is not refused, and the old PDC's
  undo can write the earlier before-image over it when the target shows the same after-image. The undo writes only
  while the target shows its own after-image, so a later change to another value is not written over (apart from
  the second-request check of a move and a new user above).
- Changes work only while the PDC emulator's own write entry is in the inventory and names the device that stands
  for the domain; if the PDC role moves to a controller without a write entry, every change is refused until the
  inventory follows it.
- Newton does not change privileged groups, delete objects, reset passwords, reset krbtgt, or change trusts,
  functional levels or Group Policy, and there is no owner-script tool for Active Directory yet.

### Fixed
- `swap-key`: when the answer to the sub-step 6 proof is lost after the router recorded it, the swap has held and no
  restore comes; the recovery now sends the proof again each round and goes on with sub-steps 7 and 8 when the new key
  works, instead of waiting two minutes and saying the router was NOT restored. The 95 s settle check tries three
  times, so one dropped call no longer fails a swap that held.
- `swap-key`: the plain key counts as refused only when ssh says the login was refused ("Permission denied"); a
  dropped link or a timeout is no longer taken as a refusal (sub-step 7, the settle check and the already-swapped
  check). Sub-step 7 says so when it cannot tell, and a rerun without `--new-key` finishes the swap.
- `uninstall`: when the link drops after the router removed the Newton key lines, the run still prints the restore
  command for each key the router listed, with a warning; a run that finds no Newton key line says that the local key
  files name the labels an earlier, cut-off uninstall removed.
- A failed upgrade's state note names the new guard and init files that stay on the router (they keep no `.prev`), and
  a note with nothing restored no longer says "first install" for an upgrade.
- `/etc/sysupgrade.conf` now also keeps the guard's state (`/etc/newton/pending`, `failed`, `boot_attempts`,
  `restore_attempts`, `lkg/` and `quarantine/`), so a firmware upgrade during a pending change still rolls it back at
  boot (19 lines instead of 13; `upgrade` adds the missing lines to an installed router).
- `--plain-key` names a key the account running the tool cannot read (the file or a folder on its path is closed to it)
  as "not readable by the ... account" instead of "file not found". `SETUP.md` step 7e and `docs/INSTALL.md` say how
  to give the `newton` account an admin key of its own for the setup commands after `swap-key`, and how to change a
  router's profile.
- The profile refusals (`newton-router-setup ... profile` and the `owrt-change.sh` handshake) name the inventory file
  and that it is edited as the `newton` account.
- The WAN-health service names its config file to procd, so a changed `/etc/config/newton_wanhealth` (new targets,
  a new interval, or enabled with no targets at first) restarts the daemon on `reload_config` instead of waiting for
  a reboot.
- `newton-bootstrap install` and `self-update` ask for the full 40-hex commit id, as the first install does, instead of
  the first 12 hex characters it had just printed.
- Owner docs: the router-entry append in SETUP.md and docs/INSTALL.md starts with a newline, so an inventory saved
  without a final newline stays readable; Claude Desktop is named as not supported; the router's approval-token check
  names the lab-profile skip (a lab router still refuses changed settings); SECURITY.md names the RouterOS (CHR) undo
  reboot; the READMEs name Python 3.11 to 3.14; docs/INSTALL.md says `newton-enrol totp` adds the authenticator on a
  no-install router too; SETUP.md and SKILL.md give the WAN-health probe traffic per WAN.
- Undo records and undo advice: when `newton_plan_undo` cannot undo a confirmed OpenWrt change because no undo record
  was kept, the refusal (and the wrapper's `NO UNDO RECORD` line) now says to plan the reverse change with
  `newton_plan_change` instead of "restore its backup by hand" (a backup restore puts back every config file as it
  was before the change, so it also reverts every later change). When the server cannot keep the undo record after a
  confirm, it now logs a `NO UNDO RECORD` line and the apply or confirm result says so in `undo_record`, so the undo
  refusal names that reason, not "confirmed before undo records were kept". The undo's check for later changes reads
  the audit log once instead of once per plan record (it took about a minute at 3000 plans).
- `owrt-change.sh`: a second apply of a session the router says was already applied is reported UNKNOWN, not NOT
  APPLIED (an earlier run applied it, so it may be live); a plan blocked by a session of this login that has no plan
  record on this host (a plan whose connection dropped while staging) says to abort it, not to apply it.
- AD: an apply the domain controller refused with `denied`, `not_found` or `unavailable` (its record reads refused)
  now names a next step (read the target and plan again, or run the DC's write setup again and plan again). Every pre-write refusal
  of a new user says to plan the user again, since its password left the plan with that apply, and a retry of such
  a plan is refused on the Newton host with that same next step instead of saying the change may already be written.
- On an installed Newton, the hints of `newton-ad-setup approval-key` and `newton-approve` (a router name or a second
  DC given to approval-key, an AD plan id given without `ad-change`, a router or scan approval with no fingerprint on
  record) name the installed launcher (`sudo -u newton /usr/local/bin/...`), since the bare name is refused there.
- A scan consent Newton refuses (already used, for another request or device, or a record it cannot use) names its cause
  (each of the five reasons a record is invalid has its own words) and the next step: plan a new scan request and ask
  the owner to approve it again.
- The Samba AD write helper's once-a-minute sweep no longer reads every transaction record ever written: a final record
  moves to the store's `done/` archive seven days after its `undo_at`, and status, confirm, abort, the undo and the
  replay check still find it there (nothing is deleted).
- An OpenWrt change the router confirmed while its answer was lost is no longer offered for undo. The status, abort or
  confirm that learns of it later no longer records the config it reads then as the config right after the change
  (a later change or an edit outside Newton could sit in it, and the undo would revert that too); `newton_plan_undo`
  refuses such a change and says why. When the router's config cannot be read right after a confirm, the wrapper says
  so in a `NO UNDO RECORD` line and the undo refusal names that reason instead of "confirmed before undo records were
  kept".
- `owrt-change.sh` next steps: a plan blocked by a session whose apply the router refused says the session is still
  staged (apply or abort it), not that its window is open; a second apply of a confirmed session says it was already
  confirmed instead of "run plan first"; a staged diff that does not match the plan is read once more before the
  apply is refused (a read cut short can still exit 0), and the refusal names the abort to run; an abort of a session
  that is gone and was never applied from this host says it was only staged, not that it may still be live.
- The ALERT and failure lines of `owrt-change.sh` name the backup the plan took, not "the latest backup" in a
  directory every router shares.
- The health check after an apply names the real `fw4 check` error, not a "disabled, ignoring section" notice printed
  before it.
- `newton-install` and the prerequisite check in `SETUP.md` and `docs/INSTALL.md` accept Python 3.11 to 3.14 only:
  the locked dependencies have no wheels for 3.15, so a newer Python used to pass the check, create the `newton`
  user and then fail while building the venv.
- `docs/INSTALL.md` steps 10e and 11d append each entry with an `echo` before and after it, so an entry file or an
  inventory that ends without a newline no longer glues two tables onto one line and makes the inventory unreadable.
- `docs/SETUP-CLIENTS.md` says the Claude Desktop entry cannot start the server and is not supported (Claude Desktop
  has no Linux build and Newton installs only on Linux); it no longer says the entry works on the same machine.
- `scripts/newton-lab-isolation` says it is passive: the Blind spots header and a `NOTE passive check` line after
  every PASS say it sends no DHCP discover or router solicitation and that router adverts can be up to 600 s apart.
- An update through `newton-bootstrap install` prints "Newton updated successfully." and the update steps (reconnect
  the MCP server, `newton-router-setup <device> upgrade` for each installed router) instead of the first-install text,
  and the bootstrap asks for every held change to be confirmed or aborted before its confirmation prompt.
- `newton-install` installs `/usr/local/bin/newton-rules` (newton user only, clean environment, the installed
  inventory) with a sudoers rule that drops the timestamp cache, and `newton-doctor` checks it like the other
  launchers. `newton-rules list` refuses when the inventory is missing instead of printing "no rules".
- `newton-bootstrap version` names a missing provenance file whose staged copy matches, instead of a "does not
  match" warning that printed two equal hashes.
- `newton-doctor` reports `sudo-only-mcp` as INCONCLUSIVE when a probe fails without sudo refusing it (an unknown
  `newton` user, a broken sudoers file, the tool failing after sudo ran it); it used to print PASS.
- The serial console tool refuses many more writes to a flash or block device node, even with `--approved`: a
  redirect, `tee`, `cp`, `mv` or `install` onto `/dev/mtd*`, `/dev/ubi*`, `/dev/mmcblk*`, `/dev/sd*` or `/dev/nvme*`,
  `dd` to one (quoted or not), `ubiupdatevol`, `ubimkvol`, `ubirsvol`, `mkfs`, `mke2fs`, `flashcp`, `flash_erase`,
  `nandwrite`, `mtd_debug write` and `erase`, `wipefs`, `blkdiscard`, `sgdisk`, and `parted`, `fdisk` or `sfdisk`
  other than a `-l` listing. Before, only the `mtd`, `dd`, `ubiformat` and `ubirmvol` spellings were refused, so
  `ubiupdatevol /dev/ubi0_1 -t` (a factory reset on NAND OpenWrt) was sent as typed. The list is a guard rail, not a
  sandbox: a write it does not name is still sent.
- A serial `push` whose line drops while it sends the `cat >` line now says the target was already overwritten and
  names the backup. The write can fail after its bytes reached the router, so it used to say the file was not written
  when the router may already have emptied it.
- A serial `push` stopped with Ctrl-C, or whose terminal hangs up, sends a Ctrl-C to take the router shell out of
  the half-sent file, says whether the target was already overwritten and where the old copy is, and exits 130; it
  used to end in a traceback with the router shell still reading the file.
- A serial `push` to a file that already has a `.newton-bak` (a retry after a push that failed) names that
  `.newton-bak` in its backup line and its failure lines: it holds the file as it was before Newton's first push,
  while the new timestamped backup holds what the failed push left.
- `newton-rules add` refuses a vantage `check_targets` entry that is not an IPv4 CIDR, and `add` and `remove`
  refuse an inventory device entry that is not a table, with a one-line message; both used to end in a traceback. An
  entry with host bits set (`10.0.0.1/8`) is read as its network, as the server reads it.
- `newton-rules` says in the header of `rules.toml` that it rewrites the file and does not keep comments, and prints a
  note when a write drops a comment the owner added; a rule's `--label` holds a note that is kept.
- `newton-vantage-setup install` and `install-client-checks` name ssh's own error text (on one printable line) when the
  admin ssh fails on the tool probe, instead of only its exit status.
- `scripts/newton-lab-isolation --from-file` names the capture file in its PASS, FAIL and INCONCLUSIVE lines instead of
  claiming `--iface` and a `--seconds` window it never observed, and a PASS adds a NOTE that the file's interface and
  time span are not checked.
- Two vendor (VyOS, RouterOS, Junos) backups taken in the same second no longer overwrite each other: the second is
  saved as `<device>-<time>-2.txt`, then `-3`, and a name that already exists, a symlink included, is never written.
- The WAN health check fails over a WAN with no UCI metric. `ip route list` prints a metric-0 route with no metric
  word, so the check never saw the route it had to move: a dead metric-0 primary kept its default route and the
  check logged it as down anyway. It now reads a missing metric as 0, for the demotion and for the restore.
- The WAN health check logs an invalid ubus device, gateway or metric once per WAN, not every round. An up WAN with
  no IPv4 default route (`wan6`, or a backup with `defaultroute '0'`) wrote the same line every 5 seconds and pushed
  every other line out of the router's log. It logs again when the reason changes, after the WAN validated or went
  down, and after a restart.
- A restart of the WAN health check during an outage no longer gives the dead WAN its route back for about 26
  seconds. The stop still restores every demoted route; it leaves a `<wan>.wasdown` mark in `/var/run/newton-wan-health`
  for each WAN that was down, and the first round after the start demotes that WAN again and keeps it down until
  `up_after` good rounds. The program is now about 218 KB.
- No-install: `newton_abort_change` on the restore plan of an owner-script change that ran is refused: it no longer
  deletes the restore script and the backup it is checked against while the receipt still points at them. The status
  of such a restore plan names the change it undoes instead of saying the change has not been applied.
- No-install: a `uci apply` that rpcd answers with an error other than busy or nothing-staged is read back. A change
  that is not on the router is a refusal (`not_applied`, the approval goes back to the owner, no receipt); anything
  else stays unknown.
- No-install: an owner-script change the router kept (its window closed with the change on the router) gets a receipt
  that says `Outcome: KEPT` and that the change is live, and its status says the change is on the router and stayed.
  The settle no longer says the change is still waiting for confirmation when it could not read the router.
- The undo line inside an apply script prints the `sudo -u newton /usr/local/bin/newton-router-setup` form the
  installed launcher accepts.
- `newton-approve` with an Active Directory plan id and no `ad-change` word names that command, and an id with no plan
  or scan request says to plan the change again; neither says "scan request not found" any more.
- `newton-enrol` checks the device name against the inventory: a typo exits 2 and lists the devices instead of
  printing "No easy grant". `grant-off` still ends a grant that is there.
- An approval answer that came back too fast to be a person says it counted as a wrong answer and names the attempts
  left or the wait.
- The terminal approval (`newton-approve`, and the owner-script run) shows the first-approval warning until the first
  approval on that device succeeds, as the dialog does, and stores the acknowledgement after that success.
- `newton_guided_audit` has a total size budget: its reads' stdout and stderr take at most 60000 characters together
  (fourteen reads of up to 64 KiB each could pass a client's output limit). A read that no longer fits is listed in
  state `truncated` with its text left out, and the result's `truncated` and `truncated_note` say so.
- The `newton_plan_change` description names every condition of the lab carve-out (a source checkout with
  `NEWTON_LAB_APPROVAL_CARVEOUT=1`, besides `lab = true` and `profile = "lab"`), says an installed Newton never applies
  it, and tells the agent to go by the plan's `requires_approval` field.
- Every tool description that returns untrusted-device-data says that Newton rewrites that text, so a diff or log can
  differ from the router's own: control bytes and ANSI escapes removed, `</` shown as `< /`, and the flag prefix on a
  line that names Newton or imitates a Newton field.
- A blocked-port client check that ends "not tested" with `no-control` or `target-dead` now says what to do: add a
  `check_controls` entry for that address to the vantage (or check that the address is up), with a pointer to
  `docs/INSTALL.md` step 11c, instead of the bare word.
- The held-apply next step and SKILL.md say that a rollback puts back every `/etc/config` file as it was before the
  apply, so any other setting saved during the window (in LuCI or with uci commit) is undone too.
- A router that holds the connection open and never answers no longer holds the MCP server. Every `owrt-change.sh`
  run has a time limit (180 s unless the apply or confirm sets its own); a plan, backup, status or abort that passes it
  says so (a timed-out plan says whether it was staged is not known, a timed-out abort is outcome-unknown and points at
  `newton_change_status`) instead of `internal server error`. `newton_read`, `newton_backup`, `newton_plan_change`,
  `newton_plan_undo`, `newton_confirm_change`, `newton_change_status`, `newton_abort_change` and `newton_guided_audit`
  run off the server's event loop, as the apply already did, so a slow one no longer blocks the confirm or abort of a
  held change.
- Every other MCP tool runs off the server's event loop too: the scan tools, `newton_plan_tier`, `newton_get_state`,
  the AD write and status tools and the local listings. A scan (up to 300 s) or a tier plan no longer holds the
  confirm or abort of a held change behind it.
- `newton_guided_audit` no longer says `ok` when its reads failed: `result` is `partial` when some failed and `failed`
  when all did, and `not_checked` lists each failed command. A command several items name (`netstat -tulpn` is named
  by three) is read once and charged to the size budget once; the later items point at it with `same_as`.
- A vendor device's listing no longer advertises `newton_guided_audit`, which refuses every non-OpenWrt device.
- The whole untrusted-device-data and rewrite notes are in the server instructions and in the OpenWrt router tools
  that return router text verbatim; the other tools, `newton_get_state` and `newton_ad_audit` among them, carry a
  short pointer, which cuts about 4 KB from every session's tool list.
- The `newton_ad_audit` description says every call collects the whole directory again (`checks` narrows the report,
  not the collection).
- `newton_ad_change_status` names `not_found` among its states, and every `not_found` answer carries a message: the
  DC holds no record of this change.
- An apply, confirm, `newton_read` or scan that runs past its time limit keeps the output it printed: a timed-out
  run hands its partial output over as bytes, and Newton threw it away. The apply's outcome-unknown result also says
  what to do next (call `newton_change_status`).
- Owner docs say what the approval gate and the undo really do. The README names both approval exceptions (a scoped
  grant and the lab carve-out) and says an Active Directory change needs only `newton-approve ad-change`; the release
  README says the chat yes is not asked inside a scoped grant. The READMEs and SECURITY.md say the router's own
  approval check runs on a router set to the prod profile or for a change Newton always asks about, and that a router
  set to lab leaves it to the Newton host. The READMEs' undo line and SECURITY.md say a guard-only restore puts the
  files back while running firewall, network and rpcd settings can stay changed until a reboot. The README's reboot
  rail is scoped to the mode, and SKILL.md lists `restored:deadline` and `restored:reboot` among the `guard=` values.
- The support table plans Linux hosts for 1.6 and firmware upgrades for later, as the roadmap does, and the lab docs
  no longer say `lab/lab.toml` is not in the repository: it is kept out of every published copy.
- A client check that a port is blocked no longer passes on silence alone. A probe that times out counts as blocked
  only when, in the same run, a control port of the same address connects: the vantage's new inventory key
  `check_controls` (`"<ipv4>:<port>"`, one per address, at most 32), or the zone's canary when the address is the
  canary's own. No control is "not tested" (`no-control`), a control that does not connect is "not tested"
  (`target-dead`), and either one blocks the confirm, so the router rolls back. A refused or open port answers as
  before. Run `newton-vantage-setup <vantage> install-client-checks` again to put the new check command and its
  controls on the vantage.
- The `newton-rules` description no longer says that Newton checks every rule with each change: the rules are
  stored, and the plan does not read them yet.
- The lab approval carve-out is off unless the lab turns it on: a `lab = true`, `profile = "lab"` device skips
  `newton-approve` only when the server runs from a source checkout with `NEWTON_LAB_APPROVAL_CARVEOUT=1` set. An
  installed Newton never applies it, so every change on it needs approval, lab or not. A plan the carve-out frees says
  `approval: lab carve-out` in its result.
- An easy grant reads whether a plan is critical from the plan's reasons, which the plan hash covers, and no longer
  from the risk word alone, which it does not: a stored plan whose risk was edited from critical to low is not covered
  by a grant. Stored plans, approvals and grants stay valid.
- Router text wrapped in the untrusted-device-data envelope is now cleaned by the envelope itself on every path
  (plan diff, apply, status, confirm and abort logs, the error result): control bytes and ANSI codes are removed, a
  closing `</untrusted-device-data>` tag is escaped, and a line that imitates a Newton field (now including
  `approval:`) is flagged. Text the read path already cleaned is not flagged twice. The owner script is still shown
  byte for byte, as the owner runs it.
- VyOS and RouterOS changes are no longer reported `confirmed` when the device reverted before the confirm: Newton
  reads the configuration again after the confirm and reports `unknown` unless it is still the change it verified (a
  Junos change already had this check). On RouterOS the comparison leaves out Newton's own `newton-revert` scheduler
  entry, which the `/export` lists while it is armed and the confirm removes; the owner's scheduler entries stay in
  it. The confirm is not sent when less than 15 seconds of the revert window are left; Newton takes the revert
  instead and says so.
- The Windows write parity tests are a release gate: a machine without PowerShell 7.4 now fails them instead of
  skipping them, unless `NEWTON_PWSH_SKIP=1` is set on purpose on a dev box. A new test runs the real `Register`
  method of the Windows undo task with the COM scheduler replaced by a local object and pins `StartWhenAvailable`, so
  a DC that was off or busy at `undo_at` still runs the undo once it can.
- The approval of an Active Directory change names its undo: an `unlock` says "Undo: none, this stays written" and
  no longer prints a Window line; every other verb says the PDC puts it back the window after the apply unless Newton
  confirms, that after a confirm only a reverse plan remains (none for `uac-clear` and `user-create`), and that the
  undo runs on the PDC only, does not cover a change made meanwhile on another DC or a PDC role move, and runs on the
  DC's wall clock.
- The guard's deadline is pinned against wall-clock jumps: a test moves the clock a year back and ten years forward
  inside the window, and the change still expires at the same uptime, neither early nor late. The guard runs `date`
  only to stamp log lines and recover directory names; a test root may now supply that `date`.
- AD audit and AD write follow-ups:
  - `newton_ad_audit` renders a large domain in seconds: the proof that no directory string reached a fix command
    strips each string once, so its cost no longer grows with findings times strings (1000 affected accounts took
    over 100 s). The tool runs off the event loop, so a long audit no longer blocks a confirm or an abort.
  - The audit report is bounded: a check lists at most 10 findings and a finding at most 10 objects, with the full
    counts in `findings_total` and `objects_total`, and the listed findings take at most 60000 bytes. A report that
    leaves anything out says `truncated` and carries a note; the tool description states the caps. The budget is
    spent finding by finding, so a check whose findings pass it together still lists the ones that fit (asked for
    alone, it lists as many as fit); a single finding that alone passes the budget is never listed, and the note says
    so.
  - `newton_ad_plan_change` against a DC that does not answer names the DC, the reason, that nothing was written and
    where to look (`devices.toml`, `newton-ad-setup`), instead of "internal server error".
  - `newton_ad_apply_change` with a malformed plan id answers "the plan record is not found or is invalid", as status
    and abort do, instead of "internal server error".
- `newton_read` with a known verb and arguments no form accepts (`uci show <junk>`) now says those arguments were
  refused, not that the verb is not allowed. `newton_plan_undo` refuses a bad id as `change_id`, its own parameter, not
  `session_id`.
- The inventory refusals say the rule: a bad device name names the name rule and that no device loads until that entry
  is fixed or removed; a bad `host` or `https_host` says what a host must look like (no URL scheme, path, spaces or
  `user@`).
- `newton-approve`: Ctrl-C or the end of input at the "Type 'approve xxxxxxxx'" prompt is a refusal ("confirmation could
  not be read; approval not created"), not a Python traceback; a wrong answer names the exact text to type, and spaces
  around a pasted answer are ignored (plan, scan and AD approvals).
- `python -m newton_mcp.approve` and `python -m newton_mcp.enrol` now run the command (they printed nothing and exited
  0, an approval that approved nothing).
- When the MCP state directory is unsafe (a symlink, a writable parent) or its redaction key is unusable, every tool
  now answers `state directory unsafe: <reason>` and returns none of the output it cannot redact. Before, a call that
  worked answered "internal server error" and a refused call crashed with the bare reason.
- A tool a no-install router does not support no longer answers that Newton "cannot manage it yet in this version"
  (false since 1.1): it names the tool, says what no-install access supports, and how the owner switches the router to
  the installed mode.
- `newton_backup` on a VyOS, RouterOS or Junos device now says (in its description and in the result: `redacted:
  true` and a note) that every secret in the saved copy is replaced with `<redacted>`, so it is a reference copy, not a
  backup to restore.
- A held change (`hold=true`) no longer ends the easy grant when it is applied: a held change has not failed. The
  grant ends when that change later fails: a confirm that returns a result other than confirmed (it says
  `EASY GRANT ENDED.`), an abort (it sets `easy_grant: "ended"`), or a status, or a confirm refused on this host, that
  finds the router rolled it back (these end the grant without saying so; a confirm refused for another reason, such as
  no held apply on this host or an unreadable hold record, leaves the grant as it was). When nobody asks and its window
  passes unconfirmed, the next apply or device list ends the grant, and so does the next plan that would lean on the
  grant (a plan the owner confirmed in chat, or one made with `NEWTON_GRANT_SKIPS_CHAT=0`, leaves it to the apply).
  A held apply whose hold record cannot be written ends the grant at once: its result says `EASY GRANT ENDED.` and
  carries no grant notice.
- A no-install apply that stopped before `uci apply` names its cause: the link failed, the router refused the login or
  a call, or Newton stopped. Each was called a link failure. It is still NOT APPLIED and the owner's yes is kept.
- A plan refused because this login's own session is busy on the router says what to do with an applied session: a
  held one is confirmed or aborted, and one applied from this host is waited for or aborted; either is rolled back
  when its window ends unless it is confirmed. It said to apply the session again, which is refused as already
  applied, and that it expires after about 45 minutes, which holds only for a staged session.
- Clearer errors (router program 1.3.3):
  - `owrt-safe-apply.sh abort` of a session that rpcd no longer has no longer prints `ABORTED.`: it says whether the
    change was rolled back is not known from there, and exits 3. `owrt-change.sh abort` says the same for a `gone`
    answer when this host's audit log cannot be read.
  - An apply refused by the router names the next step of its refusal code (plan again, approve again, the guard's
    state); "still staged" only where the session still can be applied. `no-such-txn` (the usual answer after a
    reboot) says plan again; `role` and `not-owner` name the key's missing change role and the owning login.
  - `owrt-change.sh abort` never says `ABORTED` for a `gone` answer: it asks the router's status, records a rollback
    only when that line says rolled-back (a held apply's rolled-back receipt follows it), refuses as confirmed when
    it says confirmed, and otherwise says the outcome is not known and exits non-zero.
  - After a held apply's window, `status` and `confirm` say the change is confirmed and stays live when the router's
    status line says confirmed (a confirm that reached the router after the host stopped waiting).
  - A `rollback-failed` abort carries the guard's first line, so a retry can be told from a damaged last-known-good.
  - A refused router confirm names its cause. `error too-late` adds `guard-not-pending`, `guard-window-unreadable`,
    `guard-window-short` or `rpcd-window-short`; `error rpcd-confirm-failed <code>` adds `not-lost`, `hash-mismatch`
    or `hash-unreadable`. The codes and exit statuses are unchanged.
  - A held apply whose window ended unconfirmed is recorded as rolled back once the router's status says so;
    otherwise its receipt stays unknown with a next step. The confirm refusals for a missing or malformed hold record
    and the held next step name what to do; a confirm past its timeout is outcome-unknown, not an internal error.
  - The serial tool hard-blocks a recursive `rm` of `/` or a top-level system directory (also a glob such as `/etc*`
    that matches one), and of a target it cannot resolve (`~`, `$`, a command substitution, `.` or `..`, or a
    relative path after a `cd`); `push` backs the old file up first, never over an earlier `.newton-bak`, and asks `--i-know` before it writes a login file.
  - `newton-vantage-setup check-client-checks` checks every zone; `newton-lab-isolation` reports a line with no source
    MAC as INCONCLUSIVE, never as a foreign DHCP server; the vendor lab runner takes `/tmp/newton-lab.lock`.
  - AD: a stale before-image conflict names its cause and keeps the DC's live value; a pre-write refusal adds its
    code's next step; an installed `newton-approve` no longer offers the source-tree approval-key form.
  - A damaged approval fingerprint file is named as such and counts no wrong answer, and the message gives the full
    `sudo -u newton /usr/local/bin/newton-router-setup <device> approval-key` command.
  - The serial tool's recursive-`rm` block reads every word of a command: an `rm` behind any wrapper (`timeout`,
    `nice`, `env`, `sudo`, `setsid`; even `echo rm -rf /` is refused), a command name the shell expands (`$R`), an `rm`
    that `xargs` feeds, and every quoted command line (`sh -c`, `su -c`, `env -S`, `eval`, a here-string, text piped
    into `sh`, a `-c` string attached to its option as in `sh -c'...'`). It also blocks a `find` that deletes (`-delete`, or an `-exec` that runs `rm`) from
    `/`, a top-level system directory or a start the shell decides, grouped with `\(` `\)` too. A command name built by a command substitution is not seen. It stays a guard
    rail, not a sandbox.
  - The serial tool hard-blocks `mtd` with `erase` or `write` anywhere after it (`mtd -r erase rootfs_data`, OpenWrt's
    usual factory reset), a recursive `rm` or deleting `find` of any path under `/overlay` or `/rom` (flags in separate
    words too), and a recursive `rm` of `/etc/config`, `/etc/dropbear`, `/root/.ssh`, `/usr/lib` or `/lib/modules`
    (paths below them stay allowed). `poweroff`, `halt`, `shutdown`, `opkg remove|upgrade`, `ifconfig ... down`,
    `service` or `/etc/init.d/` `network|firewall|dropbear` `stop|restart|disable`, and any command that names
    `dropbear` with a verb that stops, disables or removes it now need `--approved`.
  - Serial `push` checks the file's md5 after the byte count, so a garbled line that keeps the length is no longer
    reported `PUSHED`; every failure after the write starts says the target is already overwritten and names the
    `.newton-bak` backup (or that there was no earlier file), and a dropped serial line during a push is reported with
    exit 7 instead of a traceback. A line that drops before the line that writes the target is sent says the target
    was not written.
  - AD: a conflict whose live value is already the plan's after-image says the target holds the planned value and
    nothing needs applying, instead of telling the owner to plan the change again.
  - The release README describes the apply with hold, `newton_confirm_change` and the refused abort of a confirmed
    change, and the MCP tests that read README.md are run against the README the public tree ships.
  - SETUP.md and docs/INSTALL.md: the skill copy checks before it writes, the inventory append is safe to rerun, and
    the checkup names what each access mode can run. The installer's lock answer says the guard will be set.
- Install and operating docs:
  - docs/INSTALL.md step 10e checks for each domain controller entry before it appends it, as step 7b does, so a
    second run cannot add a duplicate table that makes the whole inventory unreadable; SKILL.md says the same.
  - docs/INSTALL.md step 11 registers a client machine for client checks and scans (the `[vantages.<name>]` entry,
    its keys, `newton-vantage-setup install` and `check`); SETUP.md and the release README point to it.
  - `newton-install` refuses a `/usr/bin/python3` older than 3.11 right after its root-program check and before it
    writes anything (`--check` names the Python it will use); a failed first install no longer says nothing was
    installed once the `newton` user, group and home exist. The prerequisites in SETUP.md, docs/INSTALL.md and
    docs/SETUP-CLIENTS.md name 3.11 and check it.
  - docs/SETUP-CLIENTS.md lists the `newton-vantage-setup` and `newton-ad-setup` launchers and their sudoers rules,
    and the approve launcher's `ad-change` form; docs/INSTALL.md step 4 lists `newton-vantage-setup`.
  - SKILL.md and the `newton_plan_change` and `newton_apply_change` descriptions: plan a change you will hold with a
    longer `timeout_s`, because the hold ends at `timeout_s` minus 15 s. SKILL.md says `hold=true` is refused for a
    zone `log_limit` (OW-FW-09) or an `ipset` change, that a VyOS, RouterOS or Junos apply confirms by itself, that
    `NEWTON_FIELD_RECEIPTS` reaches only a development server, and that an update ends with a reconnect and a router
    `upgrade`; it no longer quotes a test count. docs/INSTALL.md gives the same update steps, and SETUP.md says a
    no-install `approval-key` asks no authenticator question.
- Owner-facing claims: SKILL.md and the README name release 1.1.3 and the Active Directory audit (48 checks) and changes
  merged on main; the router's own expiry check is the installed OpenWrt router's; the scenario counts, the guided
  interview's fourteen questions and the router program of the 97-scenario Pulsar run (1.1.0) are stated as they are;
  the dev README's test counts are dated. The release README says the approval lockout and the 1.5 s minimum are the
  dialog's (the terminal `newton-approve` fallback for a router change has neither). `SECURITY.md` names the AD
  write path, `newton-enrol`, the vantage scripts and the serial script in scope, and the writes that arm no undo. The
  lab example's header says lab/lab.toml is kept out of every published copy. A test ties each claim to the tree.
- Owner-facing guarantees are scoped: the READMEs and `SECURITY.md` no longer say "the safe way", "prevent
  lockouts", "never leak" or "proven rather than claimed"; the undo is described as putting the router's settings
  back when a check fails or the change is not confirmed in time; the 96 virtual-lab scenarios are counted as files
  with no full recorded run; the lab isolation check says what it watches and what it cannot see; and the release
  README lists the GL.iNet GL-MT3000 that the support table lists. `SECURITY.md` adds the domain controller's own
  approval check, what the authenticator level and a grant leave on the Newton host, that an approved change can run
  root code on the router, and the serial console script's guard rail; "no tool runs arbitrary commands" now says no
  MCP tool. A test fails on each of those phrases, on the scenario file count, on the GL-MT3000 row, on the
  `SECURITY.md` additions and on the roadmap order.
- The roadmap order: 1.5 AD build mode, then the protocol contract (1.5.x), hosts (1.6), the security engineer persona
  (1.7) and more vendors (1.8, limited to OpenWrt, Asus, GL.iNet and what the lab can test safely). The read-only
  dashboard, a generic policy engine, maintenance windows, orchestration across systems and a third-party adapter kit
  are parked at the end of the backlog; passkey approvals get their own small approval page.
- An abort of a session that was already confirmed is refused and points to `newton_plan_undo`, instead of reporting
  success while the change stays live: the router refuses while its last session is that one (`refused <SID>
  confirmed`), and when a later session has replaced that line and the router answers `gone`, the host refuses if its
  audit log records the confirm. The router program is version 1.3.2.
- `newton-router-setup swap-key` asks before it removes the plain key from the router (`--remove-plain-key` skips
  the question), and the no-install uninstall asks before it deletes the device's owner scripts and plan records.
- `newton-doctor` reports FAIL when the router check printed a failed proof, whatever its exit code.
- A correct passphrase clears the count of wrong answers, on both the OpenWrt and the AD approval paths.
- The lab runner checks a VM's name before it rolls the VM back (`vm_name` in the lab file is now required for VM
  devices), and two runs of it can no longer use the lab at the same time (`/tmp/newton-lab.lock`).
- `owrt-change.sh` messages when a step fails part way:
  - A change the router confirmed whose answer never reached this host (the apply or confirm ended `OUTCOME
    UNKNOWN`) is recorded as confirmed by the next `status`, `abort` or `confirm` that finds the router saying
    confirmed: a `CONFIRMED ... (reconciled: ...)` line after the config hashes, from which the server writes the
    confirmed receipt and the after-hash, so `newton_plan_undo` can undo it. An undo accepts an unknown receipt
    followed by a confirmed one (a held apply that was confirmed); any other pair of receipts is still refused.
  - A second confirm whose check fails on a session the router already confirmed says it is confirmed and stays
    live, instead of saying the router rolls it back.
  - A plan that fails after staging (a refused, lost or malformed seal, or a staged config that fails `fw4 check`)
    says "discarded" only when the cleanup abort worked; otherwise it names the session still staged and the abort to
    run. A seal or stage whose link dropped is a connection error, not a router refusal.
  - A plan refused because a session of the same login is still open names that session and how to apply or abort
    it; the plan's `next:` line carries the planned timeout (and the `--hold` form). An apply refused for a different
    timeout says the session is still staged and to apply with the planned timeout.
  - The reads before an apply name the router's refusal and its next step (a session gone after a reboot says plan
    again, not "still staged"); an unreachable router after a rollback is reported as health or DNS/DHCP not
    checked, not as a difference.
  - A backup never overwrites another of the same name, and a truncated one is removed.
  - Ctrl-C says the router rolls an unconfirmed apply back at the end of its window (once the confirm was sent, it
    says only that the outcome is not known from here and names `status`); a second apply of an applied
    session says it was already applied, not `OUTCOME UNKNOWN`; a second abort of a session aborted here says there
    is nothing to do; a changes file with CRLF line endings is refused with that reason before any ssh call.
- A no-install apply whose link to the router fails before `uci apply` is sent (the login, the pending check, the
  staging), or that the router answers busy or refuses, now says `not_applied`: the approval can be used again, no
  receipt is written, and `newton_abort_change` drops the plan. It used to say `unknown` and spend the approval.
- `newton_plan_undo` of a change applied with `hold=true` and then confirmed is no longer refused for having more than
  one receipt: UNKNOWN receipts followed by one CONFIRMED receipt are one confirmed change; any other set of several
  receipts is still refused.
- The receipt of a no-install change no longer tells the owner to restore a full backup with `sysupgrade -r`. An
  owner-script change names its restore script (the `owner-run` command of its restore plan) and says the host-side
  copy holds only the UCI sections the change touches; a change Newton applied itself says no backup was kept and
  that the way back is a reverse change planned with `newton_plan_change`.
- A no-install apply that never ended (the MCP server was killed, or the client went away) no longer leaves
  `newton_change_status` at `in_progress` and `newton_abort_change` at "an apply is in flight" for ever: once its
  rollback window and the settle after it have passed, the status says `unknown` with a note that the apply did not
  finish, and the approval is marked used. An outcome the apply recorded before it stopped is kept.
- Setup script follow-ups:
  - `newton-rules add` for a zone with no inside vantage (or a mistyped zone) names the zones the device's inside
    vantages carry and points to `newton-vantage-setup`.
  - `newton-vantage-setup check` and `check-client-checks` on a vantage that ssh cannot reach (exit 255) name ssh's
    error instead of saying the key is not forced and advising a root password.
  - `newton-router-setup check` FAILs with `not fully installed` when the program or the guard is on the router but
    `/etc/newton/device-id`, `profile` or `zones` is not (an install that was cut off), and names the install
    command. Uninstall, and a re-run of install, remove any `.new` a cut-off upload left next to a code file.
  - `newton-router-setup revoke` of a label with no key line on the router and no local key file (most likely a typo)
    stops and lists the Newton key labels the router has, instead of printing `PASS already revoked`; a revoke of the
    key the inventory's `key_file` names warns that Newton is now cut off and gives the `add-key` restore command.
  - `swap-key` without the plain key says to run install first or to name the key with `--plain-key`.
  - The install writes `/etc/config/newton_wanhealth` (when it is absent) with the `main` section, disabled, so
    setting `newton_wanhealth.main.enabled=1` has a section to set; the install text also names the `iface` and
    `target` lists the check needs before it probes anything.
  - `install` and `upgrade` also write that disabled `main` section into an EMPTY `/etc/config/newton_wanhealth`,
    the file the install made up to 1.1.3, so the WAN-health enable step works on those routers too; a file with
    content is left as it is, and `upgrade` never enables or starts the WAN-health check.
  - On the plain-key admin path (`--admin plain-key`), `uninstall` proves the admin key login before and after the
    removal instead of a root password login, so it works on a router that refuses root passwords. `check` still
    FAILs a refused password login and now says why and which option every later setup command needs there; the
    approval-key login error names that option too. `docs/INSTALL.md` step 7e and `SETUP.md` say that after
    `swap-key` such a router needs `--admin plain-key --plain-key <your admin key>` on every later setup command.
  - `newton-router-setup <device> profile lab|prod` refuses a value that differs from the inventory's profile and
    names the `devices.toml` field to change first, instead of writing a profile the controller then refuses; the
    controller's profile-mismatch error names the inventory field and the `profile` command.
  - `newton-router-setup rollback` refuses a router with a pending change or a live helper lock, as `upgrade` does,
    and it and the usage text say it puts the router program from before the last upgrade back and that Newton calls
    fail until this host runs the same version.
  - `SETUP.md` step 7f says a no-install setup already asked for the approval passphrase in step 7e, so approval-key
    there is only for changing it.
- The Samba DC's sweep timer no longer looks healthy while it does nothing: `newton-ad-samba-write --sweep` (and the
  one-shot `--undo`) exit non-zero when the answer is not `ok`, so systemd records the run failed, and a sweep whose
  transaction store cannot be listed answers `error` instead of `ok` (it logs the same line when it runs before a
  request). Over SSH the helper still exits 0 whatever the answer.
- The AD read-back after an apply gives each DC its own 120 s to show the change, instead of one 120 s shared by every
  DC (a slow first DC no longer gets the next DCs marked `not_tested` and the change aborted). The read-back as a whole
  now ends 150 s before the end of the DC's undo window (counted from when the apply was sent): no read starts after
  that, each read session is given only the time left, and the DCs not read by then are `not_tested`. So a domain with
  many write DCs, or DCs whose sessions hang, can no longer keep Newton reading past the DC's own undo.
- An AD move that a DC refuses with `conflict` because it cannot read the object's current parent (the parent was
  deleted, or the write account cannot read it; the DC answers an empty parent) no longer says another change reached
  the target: the result says the DC could not read the parent and asks the owner to check it and the write
  account's read rights before planning again.
- `newton-ad-setup approval-key <device>` no longer writes over a router's approval fingerprint: the name must be the
  AD write entry of the inventory that stands for a domain (a router name is refused and the refusal names
  `newton-router-setup <device> approval-key`; a second DC's entry is refused and the domain entry is named). Run again
  with the same passphrase it changes nothing; a different passphrase replaces the recorded fingerprint only when you
  type `replace`. The installed launcher now passes the inventory path, as `newton-approve`'s does.
- A second run of the DC write setup no longer changes the DC's approval key in silence: step 3 compares the key of
  the passphrase typed now with the installed one, changes nothing when they match, and stops with the key kept when
  they differ (a mistyped passphrase used to make every later apply fail with `bad_token`). The `bad_token` next step
  now also names the way out when every approval is refused: run the DC's write setup again with the domain's
  passphrase and compare its fingerprint with the one `newton-ad-setup approval-key` printed. The Windows form of
  this step is checked by static tests only; the Samba form is run by the tests.
- A VyOS, RouterOS or Junos change whose apply and verify run close to the plan timeout is no longer thrown away while
  the device's revert window still has time: the 15 s confirm margin now counts against the window the device arms
  (VyOS and Junos: the timeout rounded up to the minute, at most ten minutes; RouterOS: never less than two minutes),
  so the log that the window was about to end is true when it is printed. A plan timeout over ten minutes on VyOS or
  Junos, which arms only ten, is no longer confirmed after the device's own revert.
- The recovery waits of a VyOS, RouterOS or Junos change (the read back after a refused line, the abort and read back
  after a failed verify, the abort of `newton_abort_change`, the wait for the timer after a confirm) now count the time
  of their SSH sessions as well as their five-second pauses, and the abort and read back of one recovery share one
  bound. A device whose sessions all hang until their timeout used to hold `newton_apply_change` for up to about three
  hours; the wait now ends within its 150 s plus the sessions of the last try.
- The first install prints "Newton installed successfully." and its closing steps only after `newton-bootstrap` is
  installed as well; when that last step fails it says that Newton was installed but the bootstrap was not, and to
  remove the bootstrap file if it is there and run the installer again.
- A failed upgrade says the previous installation was restored only when moving it back worked; otherwise it names
  the backup directory to move back by hand.
- The update steps say not to use Newton until Claude Code is restarted or `newton` reconnected: the running server
  can load the new files from disk next to its old code.
- The managed-settings advice of `newton-install` and `newton-doctor` gives the whole `{"allowManagedHooksOnly": true}`
  object when the file is missing or not valid JSON, and the one line only for a JSON object without the key.
- `newton-doctor` counts the sudo-rs refusals ("I'm afraid I can't do that", "interactive authentication is required")
  as refusals, so `sudo-only-mcp` can pass on a machine whose sudo is sudo-rs.
- CI runs every suite on Python 3.13 and 3.14 as well, the versions the installer accepts.

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

[Unreleased]: https://github.com/kevwillow/newton-senior-engineer/compare/v1.4.1...HEAD
[1.4.1]: https://github.com/kevwillow/newton-senior-engineer/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/kevwillow/newton-senior-engineer/releases/tag/v1.4.0
[1.1.3]: https://github.com/kevwillow/newton-senior-engineer/releases/tag/v1.1.3
[1.1.2]: https://github.com/kevwillow/newton-senior-engineer/releases/tag/v1.1.2
