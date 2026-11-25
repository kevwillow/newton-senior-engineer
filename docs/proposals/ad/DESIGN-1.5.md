# Newton 1.5 design: AD build mode (revision 2, 2026-11-11)

1.4 lets Newton change an existing domain. 1.5 lets Newton build a new one: a fresh Windows Server 2025 becomes a
hardened forest root, optionally with a replica DC, from one plan the owner approves once, with a fresh yes before
every stage that cannot be undone. Nothing here is built. Task 0 measurements: `MEASURED-1.5.md`. Revision 2 answers
the cold review in `REVIEW-1.5.md`.

## Decided

- 2026-11-08: greenfield only; opt-in per build (without it, Newton writes the stages as owner-run scripts, the 1.4
  script tier); approve once through `newton-approve`, never in chat; a fresh yes before each irreversible stage; a
  checkpoint before each of those; any deviation stops the run, and a changed plan needs a new approval; the build
  credential is removed at the end; the 1.3 audit is the acceptance test.
- 2026-11-10: approach A, a signed build helper on each server. Checkpoints: a VM snapshot first, a backup when no
  hypervisor is reachable.
- 2026-11-10: nothing is set up on the supernova host; the hypervisor adapters are tested in nested NLAB VMs.
- 2026-11-10: the second DC is in 1.5, as an optional stage.
- "Training" means a sourced baseline file plus skill text that teaches the interview and the judgement calls. There
  is no customer; the build is a teaching target.
- Stage 7 uses option B (the maintainer, 2026-11-11; section "The second DC").
- Ruled by the maintainer, 2026-11-13: stage 9 runs under the plan token, never a stage token; the checkpoint verifier is given the stage,
  and on wbadmin stages 2 and 7 need a bare-metal (all-critical) backup; a stage approval needs a plan approval that
  has not expired; the 1.5 build lab moves to apollo (section "The lab"), which replaces the 2026-11-10 supernova
  lab and its "nothing changes on apollo".
- Ruled by the maintainer, 2026-11-15 (R1, stage 8): stage 8 is generated from the signed plan and Newton runs it. The plan grammar gains
  the newton-ops public key (`ssh-ed25519` only, a base64 body, no comment or options) and the sha256 of the 1.4 write
  helper (`write.ps1`) the stage installs. The helper bytes come from the installed Newton, and the stage refuses when
  their sha256 is not the plan's. Stage 8 renders the 1.4 newton-ops setup through the 1.4 setup generator's own code
  paths (never a copy that can drift), with its own read-backs. Every new field changes the digest; the golden plan
  bytes and digest are re-pinned deliberately.
- Ruled by the maintainer, 2026-11-15 (R2, stage 10): stage 10 reads through the read-only `newton-audit` login (the 1.3 collector), not
  newton-ops and not the build helper. It passes only when newton-build is gone and the 1.3 audit has no finding
  outside the plan's accepted list; otherwise it stops `build_account_remains` or `finding_outside_accepted`.
- Ruled by the maintainer, 2026-11-15 (K16, stage 7): stage 7 rotates DC2's machine account password after DC2's promotion (the offline
  domain join blob carried it). The method is measured first (`Reset-ComputerMachinePassword` or
  `Test-ComputerSecureChannel -Repair` on DC2 in its own context, or `netdom resetpwd` from DC1); no credential passes
  through Newton. The read-back: pwdLastSet on DC2's computer object advanced past the promotion, and the secure
  channel holds.
- Ruled by the maintainer, 2026-11-15 (K17, stage 7): the replication read-back polls for up to 30 minutes until `repadmin /showrepl`
  shows 0 failures both ways and dcdiag passes on both DCs, then stops `readback_failed`. It never forces a KCC run or
  a sync. How long it takes is measured on the lab.
- Ruled by the maintainer, 2026-11-15 (K19, stage 7): DC1 may make three runs under one stage 7 token (the provision, the install, the
  read-back), as an exception for stage 7 only. Each run must follow the phase before it, as DC1's own journal
  records it, or it is refused `out_of_order`. Pwsh tests pin it; no other stage has the exception.
- Ruled by the maintainer, 2026-11-16 (open point 37, stage 9): stage 9 removes only the build account's own Match block from
  `sshd_config`, with its keys file, the helper, K and pw.bin as before. It never restores
  `sshd_config.bak-newton-build`, so the newton-ops block stage 8 wrote survives.
- Ruled by the maintainer, 2026-11-16 (open point 34, stage 8): stage 8 installs both logins on DC1, the one DC whose graph has stage 8
  (open point 67 asks about DC2): newton-ops, the 1.4 write path, with the plan's `ops.public_key` and the write helper whose sha256 is `ops.write_helper_sha256` (the helper
  checks that sha256 too); and newton-audit, the 1.3 read-only audit login that stage 10 reads through.
- Ruled by the maintainer, 2026-11-16 (open point 35, stage 10): stage 10 keeps stopping `unknown_outside_accepted` on any UNKNOWN outside
  the accepted list.

## The property

The helper on each server holds K and runs only stage templates compiled into it, with parameters it reads from the
approved plan's own bytes. Without the owner's passphrase, a compromised Newton machine cannot run a stage, change a
parameter, or learn a domain credential. Every rule below exists to keep that true.

## The bootstrap (owner-run, once per server)

Newton renders one script per server; the owner runs it on the fresh server. It:
- installs OpenSSH if needed, starts sshd once so `sshd_config` exists, and backs it up;
- creates a local `newton-build` (random password, never shown, DPAPI LocalMachine in `C:\NewtonBuild\pw.bin`, ACL
  SYSTEM and Administrators) in Administrators, and its keys file;
- writes `Match User newton-build,<netbios>\newton-build` (NetBIOS in lower case) with `ForceCommand` for the helper,
  `PermitTTY no`, `AllowTcpForwarding no`, ahead of the administrators block, and sets `PasswordAuthentication no` and
  `KbdInteractiveAuthentication no` globally, so a UPN-form login cannot fall through to a password shell;
- sets the SSH firewall rule to `-Profile Any`;
- on a Proxmox guest, installs the VirtIO serial driver and QEMU-GA;
- installs `build.ps1` and K = `derive_k(passphrase, device)`;
- on DC1, installs the stage 8 templates and the 1.4 write helper at `C:\ProgramData\Newton\ad-build\s8-write.ps1`,
  ACL SYSTEM and Administrators, and prints its sha256 for the owner to compare with the plan's
  `ops.write_helper_sha256` (the maintainer's decision of 2026-11-19 on the stage 8 transport, open point 78).

## The plan

One canonical document, `newton-ad-build-v1` (ASCII, one `key=value` per line, sorted pairs; the 1.4 request format).
Its digest is the sha256 of those bytes. It holds:
- the domain: DNS name, NetBIOS name, functional level, site, OU tree, groups, the owner's admin account name;
- each server: device name, role (`dc1` or `dc2`), hostname, IP, prefix, gateway, DNS forwarders, checkpoint method;
- the baseline version and the option chosen for each setting that has options;
- the stage graph per server (below), each stage `read`, `reversible` or `irreversible`;
- the accepted 1.3 findings, each with a reason code;
- for a resumed plan: `resume_from=<digest of the plan it continues>` and `start_stage=<n>`.

Values enter only through grammars (names, DNS labels, IPv4, enums). No free text, cmdlet name or script.

Every request to a helper carries the full canonical plan bytes. The helper recomputes the digest, checks the token
against it, and reads its parameters from those bytes; nothing outside them reaches a template.

## Tokens

All tokens are `approval_token(K_server, digest, NBF, EXP)`. Each server has its own K, so `newton-approve` derives
every server's K from the one passphrase and writes a token per server.
- The plan token, per server, over the plan digest: covers that server's `read`, `reversible` and `final` stages
  (stage 9, the cleanup, is covered by the plan approval; the maintainer, 2026-11-13); 6 hours. A stage token never opens stage 9.
- A stage token, per server, over `sha256("newton-ad-build-stage-v1\nplan=<digest>\nstage=<id>\ncheckpoint=<id>\n")`:
  one per irreversible stage, 30 minutes. `approve_ad_build_stage` first checks that the plan approval is still open
  (now before its EXP; otherwise it refuses with `expired` and names the command that re-approves the plan; the maintainer,
  2026-11-13), then verifies the checkpoint itself through the adapter (not from the runner's state files), prints it
  and its restore cost, then writes the token. The checkpoint id is in the signed bytes, and the helper records it in
  its journal.

The helper refuses: a bad or expired token (`bad_token`, `expired`); a stage not next in its own graph
(`out_of_order`); a stage already done (`already_done`); plan bytes whose digest differs from the journal's, unless
the plan's `resume_from` equals the journal's digest and its `start_stage` is the journal's next stage, and its
`secrets_from` is the salt the journal records (`plan_mismatch`; open point 71); a stage 2 run whose token leaves less than 210 s, the time a promotion needs (`window_short`, see
"The build account after promotion").

## Secrets

The DSRM password and the owner's first admin password are never generated by the runner. Both are derived from K:
`HKDF-SHA256(K, salt=<plan digest>, info="newton-ad-build-dsrm-v1" | "newton-ad-build-admin-v1")`, encoded to the
complexity rules. `newton-approve` derives and shows them once in the owner's terminal; the helper derives the same
values on the DC. Nothing transmits them, and the runner never holds them. Inside the helper they go to the scheduled
task through a DPAPI LocalMachine file deleted after use, never on a command line or in script text.

As built (task 8 part E fixes, 2026-11-17; open points 71 and 72): the salt is the digest of the build's first plan.
A resume plan carries that digest as `secrets_from`, in its signed bytes, so its approval and its helper derive the
passwords the first plan installed. `newton-approve` shows each DC's DSRM password, each from that server's own K
and labelled with its device, and the admin password from DC1's K.

## Stage graphs

DC1: `0, 1, 2, 3, 4, 5, 6, 7(dc1 part, only with a DC2), 8, 9, 10`. DC2: `0, 1, 7(dc2 part), 9`. Stage 10 runs only
from DC1, through the read-only newton-audit login (the maintainer, R2).

| # | Stage | Kind | Read back |
|---|---|---|---|
| 0 | Preflight: Server 2025, workgroup, no AD DS, the IP, prefix and gateway already equal to the plan's, the clock within 5 minutes of the request's NBF, 20 GB free, the plan's DNS name does not resolve (`domain_exists`), on Proxmox the QEMU-GA service running and the VirtIO Serial device OK | read | every precondition |
| 1 | Base: hostname, time source, DNS forwarders, features (AD DS, RSAT, Windows Server Backup); the IP is not touched | reversible (reboot) | name, features |
| 2 | ⛔ Checkpoint (workgroup), then promote the forest root with integrated DNS at the plan's level; after the boot add newton-build to Domain, Enterprise and Schema Admins; reboot again until `msDS-GenerationId` is on DC1's computer object | irreversible (2+ reboots) | dcdiag, SYSVOL and NETLOGON, SRV records, levels, the memberships in an S4U token, `msDS-GenerationId` |
| 3 | ⛔ Checkpoint (DC), then enable the AD Recycle Bin | irreversible | the feature's scope |
| 4 | ⛔ Checkpoint (DC), then `Update-LapsADSchema` and the computer self-permission; then remove newton-build from Enterprise and Schema Admins; then reboot DC1 (the maintainer, 2026-11-13) | irreversible (reboot) | the schema attributes (absent before, measured), the OU ACE, the memberships; after the boot, newton-build in neither Enterprise Admins (519) nor Schema Admins (518) in the directory and in the S4U key login's own token (`privileged_groups_remain` otherwise) |
| 5 | Structure: OU tree, groups, the owner's admin account, Protected Users, the password policy, a fine-grained policy for admins, the built-in Administrator per the baseline option (a derived random password, or disabled) | reversible | every object and value |
| 6 | ⛔ Checkpoint (DC), then the baseline GPOs, created and linked | irreversible: security settings tattoo the DC and unlinking does not revert them | GPO versions, secedit and registry read-back |
| 7 | ⛔ Optional replica DC (see below) | irreversible (reboots) | repadmin 0 failures both ways, dcdiag on both, `msDS-GenerationId` on DC2 |
| 8 | DC1 only: the 1.4 newton-ops setup and the 1.3 newton-audit setup, generated from the plan, then a SYSTEM task restarts sshd | reversible | its own read-backs (open point 63) |
| 9 | Cleanup, DC2 first, then DC1: remove newton-build from Domain Admins, then a one-shot SYSTEM task removes the build account's own sshd Match block (the backed-up config is not restored, so stage 8's blocks survive), the keys file, the helper, K and pw.bin; on DC1 the same task deletes the domain account last | final (Newton loses its build access) | — |
| 10 | Acceptance, through the read-only newton-audit login (the 1.3 collector): newton-build is gone, the 1.3 audit has no finding outside the accepted list | read | the audit |

The functional level is set at forest creation, so there is no raise stage. NTLM restrict is a judgement call the
skill explains after stage 10.

## The build account after promotion

- Promotion keeps newton-build's SID; sshd sees it as `<netbios>\newton-build` (measured).
- A key login is S4U. Measured: it lacks groups added after the session's tickets until a reboot, and GPO edits over
  it failed with "access rights" 3 times in 32. So every post-promotion stage runs in a scheduled task registered
  with newton-build's password from pw.bin (a batch logon; measured: the groups present at once, GPO edits 7 of 7,
  the LAPS schema update passes). Stage 2's second reboot also refreshes the S4U groups.
- The S4U key login also keeps groups it was removed from until a reboot (measured: Enterprise and Schema Admins after
  `Remove-ADGroupMember`). So stage 4 ends with a DC1 reboot (the maintainer, 2026-11-13), like stage 2, and its post-boot status
  waits for `Get-ADDomain`, then reads newton-build's groups in the directory (the `s4-groups` op, in the helper's own
  session) and in the helper's own token (`whoami /groups`): both must show neither RID 519 nor 518 for `done`; either
  showing one stops `privileged_groups_remain`, naming the check (`directory_groups` or `s4u_token_groups`); a read
  that fails or is malformed stops `readback_failed`. The rebooting stages are 1, 2 and 4.
- The task does not write the journal; the helper does, and a dropped SSH session cannot leave the journal behind the
  directory for good. Each op writes its output, then, as its last act, its exit code to `C:\NewtonBuild\out\<op>.rc`
  (created new and flushed). The helper clears an op's `.rc` before the op runs (stage 2's post-boot `.rc` files before
  each `rebooting` entry), starts the task and waits for its `LastTaskResult` at most 10 minutes (the longest measured
  op, the promotion, took 139 s); a run (stages 2 to 4) also never waits past the token's EXP less 30 s, so its
  `running` answer comes back while the token is open (a post-boot status waits its 10 minutes unclamped); stage 2
  computes that wait after its role read. A stage 2 run with less than 210 s left on its token (180 s for the role
  read and the longest measured promotion, 144 s from the helper's call, with room, plus the 30 s) is refused
  `window_short` before anything starts (every stage 2 run, a resumed one that will not promote included), so a
  promotion starts with its measured time left for the run's first answer; the check is made once, and a promotion
  that outlives a wait a slow role read shortened is answered `running` and recorded by the status record path. The task is
  never stopped, and no stage 2 run starts while one of its tasks still runs. Before giving up on a task that did not start in 120 s, the helper disables
  it and reads it again, so a task that started in that moment is waited for.
- The status record path: a status of a stage 2, 3 or 4 left `started` (the session dropped, or the task outlived the
  wait) answers `started` while the task runs; once it is over, it parses the op's `.rc` and output exactly as the run
  would have and writes the terminal entry (`done`, `stopped`, or for stages 2 and 4 `rebooting` and the restart); no `.rc` is
  `stopped`/`op_failed`. It records only under the plan the stage started under (a resume plan runs the stage itself,
  stage 2 reading the role first) and never runs an op. Its bound is the rebooting stage's: EXP plus 15 minutes. Past
  it, a task still running is refused `expired` naming the task (never `done`); once the task is over, its `.rc` is
  still recorded, except that stages 2 and 4 do not restart and stop `grace_passed`, and no `.rc` stops `grace_passed`. So
  the journal never stays `started` once the task is over.
- A status after a boot while a post-boot op of an earlier request (s2-groups, s2-genid, s2-read) still runs answers
  `rebooting` (in progress) and writes nothing; once it ends, the next status records from its `.rc` instead of running
  it again.
- After every reboot the helper waits until `Get-ADDomain` answers (measured: about 70 s after ADWS says Running).

## The second DC (stage 7): option B (the maintainer, 2026-11-11)

The domain-admin credential must not pass through Newton. Options:
- **A. Script tier (not chosen; stays the script-tier fallback).** DC2's promotion is an owner-run script; the owner types a domain-admin credential on DC2.
  Newton takes the checkpoints before and does the read-backs after. Simplest; no credential exposure.
- **B. DC1 promotes DC2 (chosen).** DC1's helper creates an offline domain join blob
  (`djoin /provision`) for DC2; Newton carries the blob (a machine secret, not an admin credential) to DC2's helper,
  which joins with `djoin /requestODJ` and reboots. Then DC1's helper, in its own password session, runs
  `Install-ADDSDomainController` on DC2 over WinRM with Kerberos, passing the credential DC1-to-DC2 inside that
  session. The credential never leaves the DCs. To be measured before it is built.
- Rejected (revision 1): DC1 releasing newton-build's password to Newton. During stage 7 a compromised Newton could
  have used it to take the domain.

## Checkpoints

Every adapter answers `verify(server_cfg, cp, kind, *, stage, not_before) -> bool`; the stage goes by keyword (the maintainer,
2026-11-13), because the kind does not tell DC1's stage 7 from stages 3, 4 and 6. An adapter that cannot take the stage
cannot answer, and the stage is refused.

`not_before` (task 7 triage, B1 and M1) is the earliest UTC second the checkpoint may have been taken at. The caller
passes it on every verify call, with no default: the later of the plan approval's NBF and the recorded completion of
the stage before (for stage 3, stage 2's). The runner and `newton-approve` take that completion from the helper's
journal (task 8). A checkpoint taken before the bound is unverified, whatever else it holds. So stage 2's pre-promotion
snapshot or backup, with good freeze lines and the `msDS-GenerationId` the DC holds by verify time, is never the DC
checkpoint of a later stage, and a checkpoint of an earlier run never verifies. The time compared is the one the
checkpoint itself reports. On Proxmox that is both the snapshot's `snaptime` and the UPID's start time. On Hyper-V it
is the `created` time `hv-checkpoint.ps1` reports. On wbadmin it is the version identifier's minute, read as UTC,
with the bound floored to its minute; the wbadmin reader returns the DC's UTC offset with the text, and the identifier
must equal the version's local `Backup time` minus that offset (open point 3). A missing or unparsable time is
unverified. There is no skew allowance (open point 11 of task
7).

Kinds, and their read-backs:
- **Workgroup checkpoint** (before stage 2 on DC1, before stage 7 on DC2): the hypervisor lists it; Hyper-V
  `ProductionOnly`; Proxmox task `exitstatus OK` with the freeze and thaw lines and no warning between them.
- **DC checkpoint** (before stages 3, 4, 6, and of DC1 before 7): as above, plus `msDS-GenerationId` present on the
  DC's computer object (measured: a rollback to a snapshot taken before it was stored skipped the invocationID
  reset), plus on Hyper-V every partition's `dSASignature` no older than the checkpoint (measured; Proxmox's agent
  freeze records no backup, so Proxmox has no `dSASignature` check).

Methods:
- **Hyper-V:** a forced-command login on the Hyper-V host (`hv-checkpoint.ps1`): `create <vm> <name>` and `list <vm>`
  for the VMs in its allowlist file, `ProductionOnly`, `ConvertTo-Json -InputObject @(...)` so a list is always an
  array. The account is in Hyper-V Administrators and `OpenSSH Users` only (Server 2025's `AllowGroups`). Its rights
  are wider than the script, so the forced command is the boundary, and the owner removes the login after the build
  (Newton cannot; the final report says so).
- **Proxmox:** a privilege-separated token whose role holds only `VM.Snapshot` and `VM.Audit` on the build VMs, with
  an expiry at the end of the build window. Measured: `VM.Snapshot` also allows rollback and delete, and a rollback to
  a `vmstate=0` snapshot stops the VM, so a stolen token can roll the DC back and leave it off. It cannot touch other
  VMs or start the DC. The token cannot delete itself; the owner deletes it after the build, or it expires. The plan
  refuses a VM without `vmgenid` or without `agent: 1`; DC snapshots use `vmstate=0`.
- **No hypervisor:** before stages 2 and 7, `wbadmin start backup -allCritical` (bare-metal recovery) to a
  non-critical volume; before stages 3, 4 and 6, `wbadmin start systemstatebackup`. Verified with `wbadmin get
  versions` (`Bare Metal Recovery`, or `System State`, in "Can recover"). The helper takes these itself as a
  `checkpoint` action under the plan token. A system-state backup cannot undo a promotion, so it is never used for 2
  or 7: the wbadmin adapter, given the stage, demands `Bare Metal Recovery` for 2 and 7 and accepts `System State`
  only for 3, 4 and 6 (the maintainer, 2026-11-13). Restoring means a bare-metal restore or DSRM; `newton-approve` says so at
  the stop.

## The helper (Windows PowerShell 5.1)

- One JSON request on stdin, no arguments, constant-time HMAC check; the request carries the plan bytes. Nothing
  large goes over stdin: no request carries the write helper (open point 78).
- An append-only journal: `<run>.<seq>.json`, `seq` strictly increasing, CreateNew, flushed; each entry holds the
  stage, the state (`started`, `rebooting`, `done`, `stopped`), the plan digest, the checkpoint id and the boot time.
- Reboots (stages 1, 2 and 4): the promotion cmdlets run with `-NoRebootOnCompletion`; the helper records `rebooting` with the current
  `LastBootUpTime`, then restarts the server. A status request does post-boot work only when `LastBootUpTime` has
  advanced. Post-boot completion of a stage is allowed until its token's EXP plus 15 minutes; after that the stage is
  `stopped` and needs a new token. A stage left `started` is recorded by a status request under the same bound (see
  "The build account after promotion": the status record path).

## Deviation and resume

A failed read-back, an error, an unexpected precondition, or a lost connection that does not end in `rebooting` stops
the run, and the journal records `stopped` and the reason. Newton reports what it found and does nothing more. To
resume, Newton plans again from the measured state with `resume_from` and `start_stage`, and the owner approves it.

A stage 2, 3 or 4 that already ran under an earlier plan (any entry of it but `checkpointed`) reads its state first
when it runs again, so a stop after its irreversible write (`grace_passed`, `error`, a failed read-back, a lost
connection) can still reach `done` and the write is never made twice:
- stage 2 reads the role on every run (`s2-role`): already this plan's forest root skips the promotion;
- stage 3 reads the Recycle Bin (`s3-state`): the measured after-state (one enabled scope, the plan's Partitions
  container, and the Recycle Bin the one entry of its `msDS-EnabledFeature`) is `done` without
  `Enable-ADOptionalFeature`; the measured before-state (no scope, the measured FeatureScope and RequiredForestMode,
  the Recycle Bin not among the enabled features) runs the op; any other state stops `readback_failed`, no write;
- stage 4 reads the schema, the Domain Controllers OU's SELF ACEs and newton-build's groups (`s4-state`): exactly the
  measured after-state (the six LAPS attributes, the legacy one absent, exactly the three explicit SELF ACEs,
  newton-build in exactly Administrators, Domain Admins and Domain Users) goes on to the reboot and the post-boot
  group read without `Update-LapsADSchema`; the whole measured before-state runs `s4-laps`; any other state stops
  `readback_failed`, no write and no reboot.
A run is refused `out_of_order` while one of these reads (or the stage's op) still runs in its task from an earlier
request. The reads stop `readback_failed` when they fail or outlive their wait. `s3-state` prints the lines
`s3-recyclebin` prints and was not run on BUILD1 itself; its after-state is the one `s3-recyclebin` measured.

## Baseline

`mcp/newton_mcp/ad/build/baseline-2026.11.toml`, one table per setting: value, the options when there are options,
why, the source (the Microsoft security baseline for Windows Server 2025, or a named Microsoft article), and the
compatibility risk. CIS items are cited by number only, never copied. The skill text covers the interview (size,
sites, departments, old devices that need NTLM), choosing between options, and when to send the owner to the script
tier.

## Open points for the maintainer (task 6, stages 5 and 6, 2026-11-14)

The design left these open, or a measurement disagreed with it. Each one is built the conservative way, waiting for
the maintainer's decision; `MEASURED-1.5.md` "Stages 5 and 6 on BUILD1, 2026-11-14" holds the bytes.

1. The built-in Administrator's "derived random password" (the stage table) is built as a random password made with
   the CSPRNG inside the stage 5 task and never stored, shown or derived. "Secrets" names only two info strings
   (DSRM and the owner's admin) and a test pins that, so a third derived secret would be a new design choice. As
   built, nobody knows the password; break-glass is the owner's admin account or DSRM. A ruling for a derived one
   needs a third info string and `newton-approve` showing it.
2. Structure details the design does not name: the plan's groups and the owner's admin account go in `CN=Users`; the
   groups are Global Security; every OU is protected from accidental deletion; the owner's admin account joins
   Domain Admins and Protected Users only, and must change its password at first logon. The read-back holds all of
   it (`pwdLastSet 0`, the groups exactly 512, 513 and 525), so a stage 5 resumed after the owner has already
   logged on and changed that password stops `readback_failed`; the maintainer may prefer a resumed stage 5 to accept it.
3. The fine-grained policy applies to Domain Admins only (precedence 10, min length 20, the rest the domain's values).
4. Stage 6 writes the baseline with `Set-GPRegistryValue` (Registry.pol), not a hand-written `GptTmpl.inf`.
5. GPMC: stage 1 installs `RSAT-AD-Tools`, which has no GroupPolicy module (measured). Stage 6 installs `GPMC` when it
   is absent (no reboot measured). The maintainer may prefer stage 1 to install it with the other features.
6. Stages 5 and 6 are not on the status record path ("The build account after promotion" names stages 2, 3 and 4).
   A stage 5 or 6 left `started` by a lost connection stays `started` to a status request; its op's result file is
   not read, and it goes on only through a resume plan (`resume_from`, `start_stage`) the owner approves. Stage 5
   is safe to run again (it skips what exists); stage 6 is not (point 7).
7. A stage 6 stopped after its first GPO cannot be run again: the op refuses when a GPO of its name already exists.
   Resuming it needs the owner to remove the half-made GPO or roll back the checkpoint.
8. `plan_build` takes any baseline version the grammar allows; the helper refuses a version it does not hold
   (`schema`). The Python side could refuse it earlier.
9. Measured: the new forest's effective password policy is 0 / 0 / 42 / no lockout, while the Default Domain Policy's
   `GptTmpl.inf` says 7 / 24 / 42. Stage 5 sets the domain object; a policy refresh does not revert it, but the DDP
   file still says 7, so a later edit of the DDP's password settings could overwrite the baseline. Stage 5 does not
   touch the DDP.
10. The CIS numbers in the baseline (1.1.1 to 1.1.7, 1.2.1, 1.2.4) are from memory of the CIS Windows Server
    benchmark layout and were not checked against a CIS document here. The cold review doubts 1.2.4 for the reset
    counter (1.2.3 in older layouts; newer ones put the Administrator lockout item at 1.2.3).
11. The lockout threshold is 10 (the Microsoft security baseline), with no CIS number.
12. The owner's admin account (IC4 of the task 6 triage): `plan_build` refuses every account name a fresh forest
    holds (Administrator, Guest, krbtgt, DefaultAccount, WDAGUtilityAccount) and `newton-build`. Stage 5 creates the
    account with the description `Newton AD build: the owner's admin account` and, finding an account of that name,
    goes on only when it carries that exact description; any other stops the op before any `Add-ADGroupMember`
    (`readback_failed`, check `owner_admin`). The description write is not yet measured on BUILD1, and the lab's
    fresh-forest account list was not measured either (the names are the documented built-ins).

## Open points for the maintainer (task 7, the checkpoint adapters, 2026-11-14)

The design leaves these open, or a measurement asked a question it does not answer. Each one is built the
conservative way, waiting for the maintainer's decision; `MEASURED-1.5.md` "Checkpoints on BUILD1, 2026-11-14" holds the bytes.

1. wbadmin takes the all-critical backup for every checkpoint. `checkpoint(server_cfg, kind)` is not told the stage,
   and a `dc` checkpoint may be DC1's stage 7, which needs `Bare Metal Recovery`. An all-critical version lists
   `System State` too (measured), so it verifies stages 2 to 7; the design's system-state backup for stages 3, 4 and
   6 would need the stage passed to `checkpoint` as well.
2. The wbadmin backup itself is not in the helper yet: its `checkpoint` action still refuses `schema` without a fake
   table. The plan holds no backup target volume (the lab used a 24 GB `B:` disk), and the design names none, so the
   template needs a plan field the maintainer has not ruled on. The Python adapter takes the backup through a `take` callable.
3. Every adapter refuses a checkpoint older than `not_before`, the UTC second passed on every verify call (no
   default; "Checkpoints"). The caller passes the later of the plan approval's NBF and the recorded completion of
   the stage before. So stage 2's pre-promotion workgroup backup or snapshot (`m7-wg` measured) is refused as the DC
   checkpoint of stages 3, 4, 6 and 7, and so is a checkpoint of an earlier run (`m-disk-1`). The task 7 triage (B1,
   M1) found that the first build accepted both. Task 8 passes the bound from the helper's journal. Until it does,
   `approve_ad_build_stage` passes only the stage, and the real adapters refuse every stage it asks about
   (`checkpoint_unverified`; fail closed, pinned by a test). wbadmin's identifier holds only the minute the backup
   started, so the bound is floored to its minute. A version that started in the bound's own minute, but before the
   bound, is therefore accepted. That needs the backup and the whole previous stage, its approval included, to fit
   inside one minute (the shortest measured backup, the workgroup all-critical one, took under 83 s). The version
   must also be read on the server itself: the read carries the computer name it ran on, and a name other than the
   plan's hostname is refused.
   The clocks (W1 of the ccdd15e review): only a UTC guest was measured, where the identifier and the local `Backup
   time` line agreed. Microsoft documents the identifier as UTC, but nothing pinned the DC's clock to UTC, and on a DC
   east of UTC an identifier in local time would make an older backup read later by the offset and meet the bound.
   So the read also carries the DC's current UTC offset in minutes (an int, -1440 < x < 1440, as for `repadmin
   /showbackup`), and a version verifies only when its identifier is its `Backup time` (the local 12-hour line, `M/D/YYYY
   H:MM AM`, parsed exactly as measured) minus that offset, to the minute. A mismatch, a bad offset or an unparsable
   `Backup time` is unverified. That holds whichever clock the identifier uses: an identifier in local time on a DC off
   UTC never matches. The bound is compared against the identifier's UTC minute. A DST change between the backup and
   the read changes the offset, so a UTC identifier whose `Backup time` is shown in the backup's own offset no longer
   matches and is unverified (fail closed). The one case the check does not catch needs both unmeasured shapes at once:
   an identifier in local time and a `Backup time` shown in the backup's own offset, taken at a nonzero offset and
   read at offset 0 (a UTC+0 zone back from summer time); that version reads later by the summer offset. Measuring
   wbadmin on a DC off UTC, across a DST change, would settle it.
4. Proxmox, the task log: the whole log must be the measured shape: `freeze guest filesystem` first; per disk its
   `snapshotting 'drive-sata<n>'` line, apollo's four LVM thin-pool lines (`WARNING: You have not turned on
   protection ...`, `WARNING: Set activation/thin_pool_autoextend_threshold ...`, `Consider pruning ... VG archive
   ...`, `WARNING: Sum of all thin volume sizes ...`, each matched whole) and the `Logical volume "snap_vm-<vmid>-
   disk-<n>_<snapshot>" created.` line of the same disk; then `thaw guest filesystem` and `TASK OK` last. Any other
   line anywhere is unverified: a SCSI or VirtIO disk, another storage's messages (ZFS, Ceph, a directory), or a
   warning of the freeze itself, until each is measured. Measured: a freeze that fails inside VSS (the VSS service or
   the agent's VSS provider disabled) still ends `exitstatus OK` and `TASK OK` with both the freeze and the thaw
   lines; the failure is one `unable to freeze guest fs - ...` line between them, not a `WARNING:` line. So the
   design's "no warning between them" is built as "nothing between them but the measured lines".
   The thin-pool lines are allowed, not demanded (they come from the host's LVM settings, not from the freeze), and
   each disk is snapshotted once (the cross-family review of task 7).
5. Proxmox, a stopped VM's snapshot has no freeze lines (measured) and is unverified for both kinds, as the design's
   workgroup rule reads. The build takes its checkpoints of running servers, so this refuses nothing the build makes.
6. The adapters' targets are not in the plan: the Proxmox API URL, node, VM id, token id, token file and CA file, and
   the Hyper-V `hv-checkpoint` ssh argv and VM name. The caller builds the adapters with them (the owner's local
   config; where it lives is task 8's). The token secret is read from its file at each request and goes only into
   the `Authorization` header.
7. The DC reads (`msDS-GenerationId` through the `s2-genid` op's text; `repadmin /showbackup` with the DC's UTC
   offset for Hyper-V; `wbadmin get versions` with the computer name it ran on and the DC's current UTC offset for
   the method without a hypervisor, point 3) are callables. The helper has no action that runs a read outside its stage, so the transport
   that reads them for `newton-approve` (which verifies itself, not from the runner's state) is task 8's seam. The
   read is made at verify time, after the snapshot: stage 2 does not finish without `msDS-GenerationId`, and a DC
   checkpoint verifies only when it was taken at or after stage 2's recorded completion (`not_before`, point 3), so
   present then means present at the snapshot. The first build left that ordering unenforced (task 7 triage, B1).
8. `hv-checkpoint.ps1`'s answer: task 0 recorded that it answers "JSON with name, id and UTC time", not the bytes. The
   built script answers `{name, id, created, vm, checkpoint_type}` (created UTC to the second; the VM's own
   `CheckpointType`, since `Get-VMSnapshot`'s `SnapshotType` says `Standard` for a production checkpoint), refuses a
   checkpoint name already taken, and answers `failed` (exit 2) when a cmdlet fails. Its tests pin these bytes under
   pwsh with fake cmdlets; it is not run on a Hyper-V host (nothing is set up on supernova). It turns `CreationTime`
   to UTC with `ToUniversalTime()`, tested with a Utc-kind and a Local-kind value (W2 of the ccdd15e review); an
   Unspecified-kind value that is really UTC would be taken as local and, on a host west of UTC, read later. The
   DateTime Kind of `CreationTime` on a real Hyper-V host (PowerShell 5.1 and 7) is unmeasured and must be measured
   before the Hyper-V method is used. It passes the VM object to
   `Set-VM`, `Checkpoint-VM` and `Get-VMSnapshot`, never its name, since `-Name` matches without case and with
   wildcards. On a DC its read-back demands exactly the five partitions of a forest root in `repadmin /showbackup`
   (measured), each with a `dSASignature` no older than the checkpoint.
9. How a hypervisor checkpoint's id reaches the helper's journal (Newton takes the snapshot; the helper's
   `checkpoint` action makes its own id) is task 8's, with the runner: `require_verified` is the seam it calls, and
   it stops the run with `checkpoint_unverified`.
10. The plan's `vmgenid` is not compared with the VM's: Proxmox gives the VM a new one on every rollback (measured),
    so after a rollback every checkpoint would be refused.
11. Clock skew (task 7 triage). The bound comes from two clocks: the plan approval's NBF from the owner's machine,
    and the stage's completion from the helper's journal (the DC). The checkpoint's time comes from the hypervisor
    (Proxmox, the Hyper-V host) or from wbadmin on the DC. The comparison has no skew allowance. If the hypervisor's
    clock runs behind the DC's, a checkpoint taken within that lag of the previous stage's completion is refused.
    A retaken checkpoint is refused for as long as the lag lasts. That fails closed. An allowance would have to be one
    named constant, smaller than the shortest gap it must still tell apart. The gap between stage 2's checkpoint and
    stage 2's completion is long: promotion, two reboots and the `msDS-GenerationId` poll, 139 + 333 + 63 s and more
    on 2026-11-13, and `m7-wg` 07:07:26 to the stored generation id at 07:16:22 on 2026-11-14. But the gap between
    one DC stage's checkpoint and that stage's completion can be seconds (the stage 3 task took 5 s). Any allowance
    would therefore let stage 3's checkpoint pass as stage 4's. The maintainer may want an allowance anyway, or the time sync
    of the hypervisor and the DCs checked in stage 0.

## Open points for the maintainer (task 8, the runner and stages 7 to 10, 2026-11-15)

Part A of task 8 (no lab use): the helper transport, `not_before` from the helper's journal, the `newton-approve
ad-build` and `ad-build-stage` subcommands, the owner's build config, the runner, and the three MCP tools. Each point
below is built the conservative way, waiting for the maintainer's decision. Task 7's open point 3 ("until it does, the real adapters
refuse every stage") is now replaced by the journal bound: `approve_ad_build_stage` and the runner read it through the
transport, and both still refuse when the read fails, the journal records no completion of the stage before, or its
time is not a UTC second.

1. The journal's completions. A status answer now carries `completed`, each stage's `done` entry time in the
   helper's own journal (the helper's clock, a UTC second); only a status answer carries it. The approval and the
   runner read it with a status of stage 0 under the server's plan token (stage 0 is a read stage in every graph: no
   reboot, no record path, nothing written). `not_before` = max(plan approval NBF, the completion of the stage before
   in that server's graph). The run state file is never read for it.
2. The hypervisor checkpoint's id reaches the journal (task 7, open point 9) by naming it: a `checkpoint` request may
   carry an eighth field, `checkpoint`, in the plan's id grammar, only for a server whose plan method is `hyperv` or
   `proxmox`; any other request naming one is `schema`. The helper records the id as given. It cannot check it with
   the hypervisor, but the owner's stage token is over the id the approval verified through the adapter itself, so
   another id opens nothing. A request without the field keeps the old path (the fake table's id, or `schema`).
3. The DC reads through the helper (`msDS-GenerationId`, `repadmin /showbackup`, `wbadmin get versions`) and the
   wbadmin backup itself have no helper action yet (task 7, open points 2 and 7). The adapters the build config makes
   fail closed for them, so every DC checkpoint (stages 3, 4, 6 and DC1's 7) is `checkpoint_unverified` through the
   real adapters and a real build stops at stage 3. The workgroup checkpoints (stage 2, DC2's 7) through Proxmox or
   Hyper-V verify. A helper `read` action (or the reads folded into the status answer) is the next packet's.
4. The owner's build config is `ad-build.toml` in Newton's config directory (`~/.config/newton`, beside the
   inventory; `NEWTON_AD_BUILD_CONFIG` names another path). The schema is exact (an unknown key, for instance a
   `token_secret`, is refused), paths are absolute, and the file must be the owner's, a regular file and not writable
   by group or others. It holds no secret: the helper key, the pinned host keys, the Proxmox token secret and its CA
   are files it names. The Hyper-V `hv-checkpoint` argv is built from structured fields (host, port, user, key, pinned
   host keys) with the repository's locked ssh options, never a free argv. The config is as trusted as the inventory:
   an agent running as the owner's user could edit it to point an adapter elsewhere, and `newton-approve` reads it.
   The maintainer may want it owned by the approval account instead.
5. The run id. A fresh plan's run is its own plan id; a resume plan keeps the run of the stored plan whose digest is
   its `resume_from` (the helper's journal holds one run), and `newton_ad_build_plan` refuses a resume of a plan that
   is not on record. The run id is kept in the run state, which the agent can write: a wrong one only makes the helper
   refuse (`plan_mismatch`, the journal holds another run) or answer an empty journal, which has no completion and is
   refused.
6. Stage 7 in part A is only the helper's request shape with a fake stage table: DC1's part, then DC2's; both
   checkpoints are taken and verified before the one stage approval, which writes a token per waiting server. Part B
   (option B, measured first on BUILD1 and BUILD2) sets the real sequence.
7. Stage 8 (the 1.4 newton-ops setup) is not built. The 1.4 setup needs newton-ops' public key and the write
   helper's bytes, and the plan grammar carries neither, while nothing outside the plan bytes may reach a template.
   Either the plan carries the public key (a grammar of its own) and the helper embeds the 1.4 write helper, or stage
   8 stays the owner-run 1.4 script. The helper still refuses stage 8 `schema`, so a real run stops there.
   Answered by the maintainer's decision R1 (2026-11-15, "Decided"); what of it is built is point 37.
8. Stage 9's helper template is not built in this step. The runner's side is: DC2 first, then DC1, under the plan
   token only (the stage approval refuses 9, and the helper takes the plan token for it); nothing is sent to a server
   after its stage 9 answered. Unmeasured, and needed before the template: whether the one-shot SYSTEM task on DC1 can
   delete the domain account `newton-build` once that account has left Domain Admins (SYSTEM on a DC acts as the DC's
   machine account, which holds no delete right on user objects by default).
9. Stage 10 takes an acceptance read (whether `newton-build` is still in the directory, and the ids of the 1.3
   audit's findings) and stops `build_account_remains` or `finding_outside_accepted` (naming the ids, which are in the
   finding id grammar). The read through newton-ops is not wired: it needs stage 8's login, and the 1.3 audit reads
   newton-audit's collector, not newton-ops. Without it stage 10 stops `acceptance_unavailable`. Which login stage 10
   uses is the maintainer's. Answered by the maintainer's decision R2 (2026-11-15, "Decided"); what is built is point 34.
10. A session that drops on a run request: on a stage that reboots (1, 2 and 4) the runner polls the status and goes
    on only when it answers `rebooting`, or `done` after the boot; on any other stage, even a `done` status after the
    drop stops `connection_lost` ("a lost connection that does not end in rebooting stops the run"). A server that does
    not answer again within 15 minutes is `connection_lost`. Stage 7 is not polled after a drop: a session of its
    sequence that drops stops `connection_lost` at once (point 19). The maintainer may prefer a non-rebooting stage whose journal
    says `done` to go on.
11. The reboot bound is 15 minutes from the run request, polled every 20 s; past it the run stops `reboot_timeout`
    (a `started` answer that never reboots stops `status_timeout`). The helper's own bound stays EXP plus 15 minutes.
12. Stop reasons the design does not name: `journal_unreadable`, `answer_invalid`, `unexpected_status`,
    `status_timeout`, `acceptance_unavailable`, `build_account_remains`, `finding_outside_accepted`, `no_build_config`,
    and `plan_mismatch` for a plan file changed after its approval (nothing is sent).
13. A stopped run sends nothing more when it is run again; it goes on only through a resume plan. A stage approval
    that expired unused leaves the run `stopped_for_approval`: no new checkpoint is taken (the helper holds one per
    stage per plan), and the owner runs the stage approval again, which re-verifies the same checkpoint with a fresh
    bound.
14. After a server's stage 9 its helper is gone. A runner started again after DC2's stage 9 (before DC1's ended) or
    after DC1's cannot read that journal again and stops `journal_unreadable`; the run state's `finished` list is only
    a report and never lets it skip a stage (point 27).
15. `newton_ad_build_plan(mode="scripts")`, the default, returns the plan and its stage list, and no bootstrap, but
    not the owner-run stage scripts: the stage ops are rendered inside `build.ps1` from the plan bytes, and a renderer
    of them as standalone scripts is not built. `mode="agent"` stores the plan and writes each server's bootstrap
    under the state directory (0600), returning the paths, not the text.

Part B of task 8 (2026-11-15; MEASURED-1.5 "Stage 7 on BUILD1 and BUILD2, 2026-11-15"). What it changed in the
points above, none of them decided:

- Point 3: the three DC reads are built (part B0): a helper `read` action (`genid`, `showbackup`, `versions`) under
  the plan token, only for a stage that holds a checkpoint of this plan on that server (DC1's 3, 4, 6 and 7), in the
  shapes `checkpoint.py` parses, wired as the build config's adapter reads through the transport. A read never runs an
  op and never writes the journal. The wbadmin backup itself stays unbuilt (task 7, open point 2: the plan holds no
  target volume), so a `wbadmin` server's checkpoints still stop `checkpoint_unverified`.
- Point 6: the runner's stage 7 is the measured sequence (point 19). One stage approval writes a token for each
  server; both must be open, or the run takes and verifies both checkpoints and waits.
- Point 8: measured. SYSTEM on DC1 deleted `newton-build` (and a probe account that had left Domain Admins). The
  stage 9 templates are built (point 18).

16. The offline domain join blob holds DC2's machine account password, and that password stays the DC's own after the
    promotion (pwdLastSet unchanged; measured), so for those minutes a copy of a DC account's credential, the kind
    that can replicate secrets, sat in Newton's memory. Built: the runner holds it in one frame, sends it only in DC2's
    stage 7 run request (the `odj` field, padded base64 up to 32768 characters; only DC1's stage 7 run answer `started`
    may carry it), and never writes it to the run state, a receipt or a log (tests). DC1's file is deleted after it is
    read; DC2's after the join (measured). Not built: rotating the machine password after the promotion
    (`Reset-ComputerMachinePassword` on DC2 ran in its key login and changed pwdLastSet; measured). The maintainer may want it in
    DC2's stage 7 after the promotion, or option A for any owner who will not carry the blob.
    Answered by the maintainer's decision K16 (2026-11-15, "Decided"); what is built is point 42.
17. The stage 7 read-back did not hold when measured. 5.5 minutes after DC2's promotion boot, DC1 could not resolve
    DC2's DSA name, and DC2's inbound replication from DC1 had failed at its boot (1908). 11 minutes after it (read
    as SYSTEM), DC2 had three naming contexts still failing from that boot, and DC1 had no inbound connection from DC2
    yet (the KCC runs every 15 minutes). A key login cannot read the other DC's replication at all (`DsBindWithCred`
    status 5). The design's "repadmin 0 failures both ways" needs either a wait (how long, bounded by what) or a forced
    `repadmin /kcc` and `/syncall`, which are writes. Nothing was forced. So DC1's read-back run would stop
    `readback_failed` at the measured times.
    Answered by the maintainer's decision K17 (2026-11-15, "Decided"); what is built is point 44.
18. Stage 9. The removal from Domain Admins was never measured: the op's group read before it
    (`Get-ADPrincipalGroupMembership`) threw in the key login on both DCs. DC2 runs no password task after its
    promotion (its local account, and so its pw.bin, went with the SAM), and the membership is one domain-wide value.
    Built: DC2's stage 9 makes no removal; DC1's makes it in its password task, read back through `Get-ADGroupMember
    'Domain Admins'` (unmeasured), and a removal that does not read 0 after stops `readback_failed` before the cleanup
    is registered. Then, on both, the one-shot SYSTEM task (measured): after a 15 s wait for the answer, it restores
    the sshd configuration from `sshd_config.bak-newton-build`, restarts sshd, and deletes the keys file, the helper,
    K (`key.hex` in the install root, point 23), pw.bin and a leftover `dsrm.bin`. Only on DC1, last, does it delete the domain account
    (a pwsh test runs the rendered script and reads the order). SYSTEM deleted the account still in Domain Admins, so
    the maintainer may drop the removal before the delete.
19. Stage 7's sequence: DC1 provisions (its run answers `started` with the blob, check `s7_provision`); DC2 joins with
    it and reboots (`rebooting`, its status after that boot `rebooting` with `s7_member`); DC1 installs over WinRM
    and restarts DC2 (`started`, `s7_install`); DC2's status after the promotion boot is `done`; DC1's third run reads
    back and ends `done`. DC1 runs stage 7 three times under one token, which the helper's rule "a stage in flight
    refuses a second run" forbids today. A phase-by-journal exception for DC1's stage 7 needs the maintainer's approval. A runner
    that stops inside the sequence (killed, a lost session, a stop) does not pick it up again: the run stops
    `stage_interrupted`, and a resume plan does not reopen it either (point 38). The blob died with the process, and the computer
    object it made stays (a new provision would need `/reuse` or its deletion). The 15-minute bound applies to each
    wait on DC2. Every new stop: `stage_interrupted`, and `answer_invalid` for a provision answer with no blob.
    The three runs: answered by the maintainer's decision K19 (2026-11-15, "Decided"); what is built is point 41. The resume:
    point 45.
20. The helper templates of stage 7 are not built in this part. The runner, the transport's `odj` field and the
    fake helper are. Three rulings come first: point 16 (the machine password), point 17 (the read-back), and point
    19 (DC1's three runs). Until then the helper refuses stage 7 `schema`, so a real two-DC run stops at DC1's stage 7
    after its checkpoints.
    Built since (2026-11-16) under rulings K16, K17 and K19: points 41 to 45.
21. The baseline option `administrator: disabled` disables the domain Administrator at stage 5, the account the
    owner's own key login may use (it broke the lab's: stage 6's first attempt failed "Connection closed", and the
    account was re-enabled through the guest agent). The skill should say so before stage 5.
22. The cleanup leaves `C:\NewtonBuild\ops`, `C:\NewtonBuild\out`, the journal and the sshd backup file, and
    its own log `C:\ProgramData\Newton\ad-build-cleanup.txt`. None holds a secret (the op outputs hold names,
    SIDs and reads). Whether stage 9 deletes them is the maintainer's.
23. The bootstrap writes K to `C:\NewtonBuild\k.hex` and installs the helper as `C:\NewtonBuild\build.ps1`.
    The helper reads K and `device.txt` from its install root `C:\ProgramData\Newton\ad-build`, which the
    bootstrap never writes (the lab's stand-in wrote them there). So a server bootstrapped by `bootstrap.py` would
    answer no request. Fixed (2026-11-15): the bootstrap writes K (`key.hex`), `device.txt` and the helper
    (`build.ps1`) under the helper's install root, protected before K is written; the stage 9 cleanup deletes those
    paths. A pwsh test runs the bootstrap's key step and then a helper status request against what it wrote.
24. DC2's DSRM secret reaches DC2's DPAPI file `dsrm.bin` before the join, and DC1's install reads and deletes it
    inside the WinRM session (measured). A stage 7 that stops before the install leaves it there until stage 9's
    cleanup.
25. After its promotion, DC2's key login is the domain `newton-build` (Domain Admins until stage 9), S4U, with no
    password task. The reads measured in it: dcdiag, local repadmin, `msDS-GenerationId`,
    `Reset-ComputerMachinePassword`. Any write DC2's stage 7 or 9 would need there is unmeasured.

Review of task 8 (2026-11-15, fixes on `newton/1.5-t8-runner`). Built the conservative way, none decided:

26. One `start_stage` for both servers (X4). The helper takes a resume plan only when its `start_stage` is that
    server's next stage ("Tokens"), and a two-DC plan has one `start_stage`. So a two-DC build that stopped with the
    servers at different next stages (DC1 anywhere in 2 to 6 or at 8, or DC2's stage 0 or 1 stopped after DC1's ran)
    cannot be resumed through Newton: DC2's helper (or DC1's) refuses even the read of its journal. Built: the runner
    stops `plan_mismatch` before any request when the `start_stage` is outside a server's graph (2 to 6, 8 and 10 are
    never DC2's next stage), and stops `plan_mismatch`, naming `start_stage`, when a helper refuses the journal read
    of the resume plan as another plan's; nothing is run. `plan_build` still takes such a plan (the golden plan
    resumes a two-server plan at 3). A start stage per server is a plan grammar change (new bytes, the helper's resume
    rule), so it is the maintainer's decision; until then a stopped two-DC build at different next stages is rolled back or
    finished by hand.
27. The run state is the agent's (X2). The runner never skips a stage on its word: each call walks the order and reads
    every server's journal (a status of stage 0), and a stage is skipped only when the journal records it done; the
    `finished` lists are rebuilt from what the call saw. A run state that says `done` sends no helper request (stage
    9 removed the helpers) and stays `done` only when stage 10's acceptance passes again; otherwise it stops with the
    acceptance's reason. What the run state still steers only makes the runner wait or stop: the checkpoint entry of a
    stage that waits for its approval (the approval verifies the checkpoint itself) and stage 7's begun marker.
28. A runner killed during a stage, then started again (X3; PLAN-1.5 review focus 2). Before every run the runner
    reads that stage's own status: `pending` runs; `done` needs no run; `rebooting` or `started` is polled to its end
    (15 minutes from the restart), so no second run is sent. A journal read that finds no answer (the server still
    booting) is asked again every 20 s for at most 15 minutes, then stops `journal_unreadable`. A resume plan's
    `start_stage` that the plan it resumes left `started` or `stopped` (or whose status the helper leaves to the
    resume's own run, `plan_mismatch`) is run, and the helper decides. Not handled: a resume plan's start stage that
    the resume plan itself started, the runner killed before its end, is run again and the helper refuses it
    `out_of_order`, so the run stops.
29. Stage 9 journals `done` once the SYSTEM cleanup task reads `Running` (X5), before the task's 15 s wait and its
    deletions; a deletion that fails is written only to the task's own log. Stage 10's `build_account_remains` is the
    backstop for the account; nothing reads back the sshd configuration, the keys file, the helper, K or pw.bin on
    either DC (point 18).
30. `s9-register` starts the cleanup task before the helper reads its verdict (I4): a register answer read as
    `op_failed` still has the cleanup running. It fails toward less access (the build login goes), and the runner then
    finds no helper.
31. Stage 9 is not on the status record path (I5; like stages 5 and 6, point 6). A DC1 `s9-da` task that outlives
    its wait answers `started`, the runner polls it, and the run stops `status_timeout` after 15 minutes; its `.rc` is
    not recorded.
32. The installed `newton-approve` launcher (X7) now takes `ad-build <plan>` and `ad-build-stage <plan> <stage 0-10>`
    besides the plan id, and forwards exactly those words. Unchecked: the launcher's `env -i` drops
    `NEWTON_AD_BUILD_CONFIG` and sets `HOME=/var/lib/newton`, so in the installed layout `ad-build-stage` reads the build
    config at `/var/lib/newton/.config/newton/ad-build.toml`, which must be user newton's (point 4). The 1.4
    `ad-change` subcommand is not in the launcher's grammar either; it is not changed here.

The maintainer's decisions R1 and R2 and the part B review fixes (2026-11-15, `newton/1.5-t8-runner`). Built the conservative
way, none decided:

33. Stage 7's interrupted stop rests on the helpers' journals (IC-1). Before DC1's provision the runner reads DC1's and
    DC2's stage 7 status through the transport; any answer but `pending` (an entry of stage 7 in either journal) stops
    `stage_interrupted`, a read with no answer `journal_unreadable`, a refused read its own code. The run state's begun
    marker is no longer needed for the stop, so an agent that deletes it does not reopen a provision. Corrected
    2026-11-16 (a review): a resume plan that starts at 7 does not go on past a stage 7 entry; the runner has
    no resume branch for stage 7 (point 38).
34. **Answered by the maintainer, 2026-11-16 (Decided): stage 8 installs newton-audit too.** Built in task 8 part D (points 55
    to 66). The text below is kept as it was. Stage 10 reads through newton-audit (R2). The owner's build config gains an optional `[audit]` table, exactly
    `host`, `port`, `key_file`, `known_hosts` (absolute paths); the user is not a key: it is `newton-audit@<plan
    domain>`. `run_build` takes the config's acceptance when the caller passes none (the MCP tool passes none); a
    config without the table stops stage 10 `acceptance_unavailable`. The read is the 1.3 audit's own chain
    (`transport.fetch`, `wire.parse`, `runner.run` with its privileged-key and collector guards); a document of
    another domain, a users query that is not `ok`, or any guard raising stops `acceptance_unavailable`, never
    `absent`. Tests run it through a fake collector pinned to the 1.3 fixture `win-dc-audit-r3.json`. Open: who installs
    the newton-audit login on a built DC (the owner runs the 1.3 setup after stage 9, or a stage does it); until then
    the owner names it in the config, and the known_hosts it pins must hold DC1's host key.
35. **Answered by the maintainer, 2026-11-16 (Decided): stage 10 keeps stopping `unknown_outside_accepted`.** Built as
    described; nothing changed. Checks the audit could not prove (UNKNOWN) are not a pass. The acceptance answers their ids beside the findings,
    and stage 10 stops `unknown_outside_accepted` (a stop code the design does not name) when one is outside the
    accepted list. The maintainer may want them read as findings, or passed.
36. Stage 9 is reported done only on evidence. The helper's `done` of stage 9 says the SYSTEM cleanup task runs,
    not that it ran, so the runner records `cleanup: registered` for that server and leaves 9 out of its finished list.
    Stage 10 reads the acceptance again every 20 s while newton-build is still in the directory, for at most 300 s
    (`ACCEPTANCE_WAIT_S`, longer than the task's 15 s wait), then stops `build_account_remains`. The first read that
    finds the account gone marks stage 9 done and `cleanup: confirmed` on every server, since DC1's task deletes the
    account last. No evidence reads DC2's own deletions (its sshd configuration, keys file, helper, K, pw.bin); they
    are inferred from DC1's account delete only after replication, and nothing reads them back on either DC (point 29
    stands). The helper journal is unchanged.
37. **Answered by the maintainer, 2026-11-16 (Decided): stage 9 removes only the build block and never restores the backup;
    stage 8 installs both logins.** Built in task 8 part D (points 55 to 66). The text below is the state before
    the ruling. Stage 8 (R1) is built only in part. Built: the plan's `ops` section (`ops.public_key`, the strict 51-byte
    ed25519 blob in the `ssh-ed25519 <base64>` grammar; `ops.write_helper_sha256`), required, in the canonical bytes
    and the digest (the golden plan re-pinned); `newton_ad_build_plan` fills the sha256 from the installed
    `setupgen_write.WRITE_HELPER_PATH` and refuses another value or an installed Newton with no write helper; the
    approval prints the section; the runner stops `write_helper_mismatch` before any stage 8 request when the
    installed helper's sha256 is not the plan's. Not built: the stage 8 template itself. The helper still refuses
    stage 8 `schema` ("the stage templates are not built yet"), so a real run stops at stage 8, fail closed. The
    template needs, and each is the maintainer's or unmeasured:
    - a refactor of `setupgen_write.windows_write_script` into a template and a fill whose 1.4 output stays byte
      for byte the same, and a build variant that reads K from the install root instead of prompting for the
      passphrase, with no sshd restart step of its own;
    - the write helper's bytes in the stage 8 request, checked against the plan's sha256 by the helper too;
    - stage 9 restores `sshd_config.bak-newton-build`, taken before newton-ops' sshd block was written, so stage 9
      as built would remove newton-ops' login (a blocker: stage 9 must keep stage 8's block, or stage 8 must run
      after the restore);
    - the sshd restart of the 1.4 setup inside a build helper session is unmeasured, as is all of stage 8 on BUILD1;
    - K is then shared by the build path and the 1.4 write path on DC1;
    - which OUs newton-ops is delegated (the plan's top-level OUs is the conservative reading).

Review of 861cfd9 (2026-11-16, `newton/1.5-t8-runner`). Built the conservative way, not decided:

38. A stage 7 that began and did not end is never resumed by Newton, a resume plan included (IC-1 of the review).
    Before DC1's provision the runner reads stage 7's status on both servers; any entry of stage 7 in either journal
    (`started`, `rebooting`, `stopped`, `done` on one server only) stops `stage_interrupted` with the words "the owner
    decides", whatever the plan's `start_stage`. The blob died with the runner that held it, the computer object of
    the provision stays, and the fake and real helpers answer the stage 7 status by state, not by plan, so a resume
    plan cannot tell "nothing happened" from "the provision ran". What a resume plan at 7 meets, in the tests: both
    servers with 7 next (killed at the join) stop `stage_interrupted`; DC2 in flight (killed at the install) has its
    helper refuse the resume plan's journal read (`out_of_order`), so the run stops `journal_unreadable`; DC2 done
    (killed at DC1's read-back) stops `plan_mismatch` (point 26). None sends a stage 7 run. Before the stop the
    resume plan still takes and verifies both stage 7 checkpoints and asks the stage 7 approval, because the status
    read needs the stage token; the approval is spent on a stop. The owner's way out is a rollback of both servers to
    their stage 7 checkpoints, or finishing by hand. A resume branch (a status that tells the provision ran, a
    `/reuse` provision, or a DC1 read of the computer object) is the maintainer's decision and unmeasured.
    Revised by point 45 (2026-11-16): a resume plan at 7 over a provision DC2 never joined (killed at the join) now
    goes on through DC1's helper; the other two cases above are unchanged.
39. A journal read the helper refuses as `expired` (the plan token's window is over) now stops the run `expired`
    (it goes on only through a resume plan, point 13), not `journal_unreadable` (F6 of the review). Revised by
    point 52 (2026-11-16): this point first said the owner approves the plan again, which does not work. Only the
    fixed words
    `plan_mismatch` and `expired` pass from the helper's code into the transport's error; any other refusal is
    `refused`.
40. Receipts keep the helper's code and each check's name and detail as the helper answered them, with no length
    bound (F10 of the review). The helper is Newton's own forced-command script, so this is outside today's threat
    model; not changed. A grammar or a length bound on those fields is the maintainer's call.

The stage 7 templates and the part C triage fixes (2026-11-16, `newton/1.5-t8-runner`). Built the conservative
way, not decided:

41. The helper now runs stage 7 (option B) under K19. DC1's journal entries name their phase (`s7_provision`, then
    `s7_provisioned`; `s7_install`, then `s7_installed`; `s7_read`); DC2's do too (`s7_join`, `s7_member`, `s7_dc`).
    A DC1 run under the plan of the run is allowed only after `started` at `s7_provisioned` (the install) or at
    `s7_installed` (the read-back). Anything else in flight is refused `out_of_order`, and every other stage keeps the
    rule that a stage in flight refuses a second run (pwsh tests, a mutant per guard). The blob is in DC1's provision
    answer only: the helper reads the file djoin saved, deletes it in the same run, and never journals it. DC2's run
    must carry it (`odj`, padded base64, at most 32768 characters, a stage 7 run request only). DC2 writes it to
    `C:\NewtonBuild\s7-odj.txt`, which `djoin /requestODJ` reads and the op deletes, and writes its own DSRM file from
    its K. A join that stops deletes both; DC1's install deletes the DSRM file on DC2, and stage 9 deletes a leftover
    blob on either server. The provision, join and install bodies and parsers are pinned to the measured m7 outputs.
    Unmeasured, with constructed fixtures: the `repadmin /showrepl * /csv` rows the read-back parses (the measured
    read was the text form), the member read, the DC read, and DC2's restart from inside DC1's WinRM session
    (`shutdown.exe /r /t 10` once `Install-ADDSDomainController` answers Success with RebootRequired).
42. K16 is built with the one measured method: `Reset-ComputerMachinePassword` in DC2's own key login after the
    promotion's boot (the domain newton-build, S4U). The read-back runs on DC2 (`-Server` DC2). pwdLastSet after the
    reset must be greater than before it and not earlier than DC2's LastBootUpTime, and `Test-ComputerSecureChannel`
    must answer True; otherwise the stage stops `readback_failed`. `nltest /sc_verify` is logged, not checked.
    `Test-ComputerSecureChannel` on a DC and the new pwdLastSet reaching DC1 are unmeasured. The other two methods were
    not tried. Revised by point 53 (2026-11-16): the secure channel is read with `nltest /sc_verify`, and
    `Test-ComputerSecureChannel` is no longer run.
43. A provision or an install still running in DC1's password task when its wait ends stops the stage `op_failed`.
    It is not recorded later from its result file, as stages 2 to 4 are: the blob of a provision recorded later could
    not reach DC2, and an install recorded later would leave the runner unsure whether DC2 restarted. Only the
    read-back (`s7_read`) is on the record path. The owner decides; a recorded install is the maintainer's call.
44. K17's bound against the token. The read-back waits at most 30 minutes, and never past the stage token's EXP plus
    the 15-minute grace, less 120 s (so the status that records it is still inside the bound). A 30-minute stage
    token that the provision, join, member boot and install have already used leaves less than 30 minutes, so the
    read can stop `readback_failed` before 30 minutes pass. The runner waits 35 minutes for DC1's read-back
    (`READBACK_TIMEOUT_S`); every other wait stays 15 minutes. A longer stage 7 token, or a fresh token for the
    read-back, is the maintainer's call. The read polls every 30 s. It forces nothing: no `/kcc`, `/syncall` or `/replicate` (a
    test greps the rendered op). dcdiag on both DCs may fail only DFSREvent and SystemLog.
45. IC1-resume7: a resume plan at 7 now goes on with a stage 7 that DC1 began and DC2 never joined (killed at the
    join), as point 33 first said. The runner sends DC1's run again only when the plan is a resume plan at 7, DC1's
    stage 7 status is `started` or `stopped`, and DC2's is `pending`. DC1's helper then decides. It provisions again
    with `djoin /reuse` only when its own journal's last stage 7 phase is the provision's (`s7_provision` or
    `s7_provisioned`, under the earlier plan); any later phase is refused `out_of_order`. Without a resume plan, the
    stop stays `stage_interrupted` (tests). The `/reuse` provision, and the parse of a `before:` line naming the
    computer object an earlier provision made, are unmeasured.
46. F1 of the tri-c2 triage: before a checkpoint, the runner reads the helper's journal through the transport. A
    stage that already holds a checkpoint under this plan reuses it: that id goes through `require_verified` with the
    journal's `not_before`, and no second checkpoint is taken. The checkpoint request now names the checkpoint's
    name, and the helper journals it. A checkpoint recorded without a name (by a helper from before this change) is
    not offered for reuse, so the runner takes a new one (fail closed: the adapter's name is needed to verify it).
47. The DC2 status guard "stage 7 waits for a boot under another plan" survives its mutant: the helper's plan-of-run
    check refuses such a status first (`out_of_order`, "the stage the plan resumes is in flight"). It is kept as a
    second line of defence.
48. F5 of the tri-c2 triage (the receipts' check details) is the same question as point 40, and is left open there.

Review of f4cebe6 (2026-11-16, `newton/1.5-t8-runner`). Built the conservative way, not decided:

49. X3: stage 7's read-back runs dcdiag in its full form on both DCs (`dcdiag` on DC1 and `dcdiag /s:<DC2>`, both
    from DC1's password task), not `/q`. Measured, `dcdiag /q` exits 0 when tests fail and prints no line for a
    test that passed (MEASURED-1.5, stage 2 and stage 7), so a `/q` block cannot show that any test ran: a block
    holding only an LDAP error line passed. A DC now passes only when its dcdiag exited 0, every server test of
    stage 2's must-pass list has a "<that DC> passed test" line, each partition and enterprise test of the list
    (CheckSDRefDom, CrossRefValidation, LocatorCheck, Intersite) has a "passed test" line from any subject, and no
    test failed but DFSREvent and SystemLog (a failed test with no name, or one the list does not name, is a
    failure). The op's poll applies the same rule before it says it converged, and the parser also requires the
    poll's "converged True". The "Testing server:" line the review suggested is not required: no measured output
    of the build holds it (stage 2's read printed only the test lines), and the host-named "passed test" lines
    carry the same proof. Unmeasured, with a constructed fixture: the full dcdiag on a replica, and against DC2
    from DC1's password task; whether a fresh replica passes the whole list within 30 minutes; the length of the
    output. Stage 2's list was measured on a fresh forest root. If a fresh replica fails a listed test as a matter
    of course, stage 7 stops `readback_failed` (fail closed). A list for the replica is the maintainer's call, after a lab run.
50. IC-L1: DC2's DC read (`s7-dc`) throws before `Reset-ComputerMachinePassword` unless Win32_ComputerSystem
    answers DomainRole 4 (a replica DC, what the parser requires). A DC2 that rebooted by itself after the join is
    a member, and its machine password is not rotated; the status stops `readback_failed`, as before. The review
    allowed DomainRole 4 or 5. 5 (a primary DC) is refused here because DC2 is a fresh replica and the parser
    requires 4.
51. The op bodies of stage 7 (the provision, the read-back and the DC read) are now also run in the tests: the
    rendered script runs under pwsh on Linux, with fakes of djoin, repadmin, dcdiag, the AD cmdlets and the CIM
    reads, and the read-back's output is fed to the parser. This proves the bodies' own logic (the refusal of a
    computer already there without `/reuse`, the error row, the dcdiag rule, the DomainRole check). It does not
    prove what the Windows commands print; that stays with points 41, 42 and 49.

The X6 and IC-W1 fixes of a review (2026-11-16, `newton/1.5-t8-runner`). Built the conservative way,
not decided:

52. X6: a run stopped `expired` stays stopped when the owner approves the same plan again. The re-approval succeeds
    and gives a fresh token, but the run state keeps the stop (same plan digest) and a stopped run sends nothing
    (point 13). The stop's detail now names a resume plan as the way out, and a test shows a resume plan at the
    stopped stage ends done, a second approval of the same plan sends nothing, and the detail never says "approves
    the plan again". Whether a re-approval should clear an expired stop (and what it means for a run stopped while
    a checkpoint waits) is the maintainer's call; not built. Seen by the review, not changed: a second approval of the same
    plan prints the DSRM password and the first-admin password again ("shown once" is then not true). They are
    derived from the server key and the plan digest, so they are the same values, not new ones. Whether a
    re-approval should refuse, or not print them again, is also the maintainer's call.

    Note (F1 of a review, 2026-11-17; not decided): the stage approval's own `expired` refusal used to
    tell the owner to re-approve the plan in every case. For a run stopped while a checkpoint waits that is a dead
    end: the new approval's NBF raises the checkpoint's `not_before` (the later of the NBF and the previous stage's
    completion) past the waiting checkpoint, every adapter refuses a checkpoint older than the bound, and the runner
    never takes a stage's checkpoint again once the run state records one. So when the plan approval is past its EXP
    (or holds none) and the run state of this plan has a server `stopped_for_approval` at the stage with a
    checkpoint recorded, the refusal now names a resume plan at that stage (`resume_from` this plan, `start_stage`
    the stage), as the stop detail above does, and never "re-approve the plan". With no such server (no run state, a
    run state of another plan, a server at another stage, not waiting, or with no checkpoint) it still names
    `newton-approve ad-build <id>`. The run state is written by the agent; it only picks the wording here and never
    lets a stage through. Tests in `test_build_approve.py` show the old text fails and kill a mutant of each clause.
    What a re-approval should do to a waiting checkpoint (retake it, keep the old bound, or refuse) stays the maintainer's call
    with the rest of this point.

The F3, IND and F7 fixes of a review (2026-11-16, `newton/1.5-t8-runner`). Built the conservative way,
not decided:

53. F3: DC2's secure channel after the machine password reset (K16) is read with `nltest /sc_verify:<plan domain>`, not
    `Test-ComputerSecureChannel`. Microsoft's reference for the cmdlet (Windows PowerShell 5.1,
    https://learn.microsoft.com/powershell/module/microsoft.powershell.management/test-computersecurechannel?view=powershell-5.1)
    says: "This cmdlet only works on Domain Member computers. When you run it on Domain Controllers, it returns false
    positive errors. To verify and reset the secure channels for Domain Controllers, use netdom.exe or nltest.exe."
    The nltest reference (https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11))
    documents `/sc_verify` as "Checks the status of the secure channel that the NetLogon service established ... This
    parameter is only valid on domain controllers that run Windows 2000 with Service Pack 2 and later." So the
    cmdlet is not run at all, and a line of it is never read. The check was kept, not dropped: replication and dcdiag
    do not prove the channel. DC1's read-back runs after the reset, but a Kerberos service keeps accepting tickets
    made with its previous password, so DC1 can pull from DC2 under the old key until the new one replicates. dcdiag's
    MachineAccount test reads the computer object and its SPNs, not Netlogon. `secure_channel` passes only when
    nltest exited 0 and, inside the block its header counts, it printed `Trusted DC Connection Status Status = 0 0x0
    NERR_Success`, `Trust Verification Status = 0 0x0 NERR_Success` and `The command completed successfully` (each
    once, trailing blanks ignored). Those lines are constructed from the reference's `/sc_query` example and are not
    measured: the apollo lab could not run on 2026-11-16 (apollo had 4.2 GB of RAM free, under the 6 GB the lab
    rules require before a VM starts), so the fixture `s7-dc-constructed.txt` stays constructed. If a real DC prints
    them otherwise, or nltest fails in the minutes after the promotion's boot (DC2's DNS registrations failed then in
    the stage 7 measurement), stage 7 stops `readback_failed` at DC2's status (fail closed); the fix is a lab run
    and a fixture of the measured bytes. Also open: `/sc_verify` rebuilds a channel that does not work (the reference
    says so). That is a Netlogon session reset, not a directory write, but it is more than a read; `/sc_query` only
    reports the last use. The `Trusted DC Name` line is logged, not checked (DC2 may name itself or DC1). Which tool,
    and what it must print, is the maintainer's call after a lab run.
54. F2: DC2's helper checks the blob only against its grammar (padded base64, at most 32768 characters) before
    `djoin /requestODJ`; it does not check that the blob is for the plan's domain and DC2's name. The runner takes the
    blob only from DC1's stage 7 answer, and only a holder of the build login and an open stage 7 token could send
    another one (that login is in Domain Admins until stage 9). After the join's boot, `s7-member` reads DC2 a member
    of the plan's domain under the plan's name, so a wrong join stops there. Not built, the maintainer's call: parse the blob's
    domain and machine name on DC2 (the ODJ format is unmeasured beyond its length and its UTF-16 BOM), or bind a
    sha256 of the blob into DC1's journal and DC2's request.

Task 8 part D, stage 8 and the stage 9 change (2026-11-16, `newton/1.5-t8-runner`). Built the conservative way, not
decided:

55. The newton-audit key is in the plan as `ops.audit_public_key`. It uses the same grammar as `ops.public_key`
    (`ssh-ed25519 <base64>`, a 51-byte blob, no comment or options), and it is required. The planner refuses it
    when it equals the newton-ops key, and DC1's helper refuses it again from the plan bytes: with one key, the
    holder of the read-only login would hold the write login too. It changes the digest, and the golden plan is
    re-pinned (sha256 starts 93068eab). The owner's stage 10 `[audit]` config still names its own `key_file`. Nothing checks
    that this file's public half is the plan's `ops.audit_public_key`; a wrong key file stops stage 10
    `acceptance_unavailable` at the login. The maintainer's call: whether the runner should compare the two before stage 10.
56. newton-ops is delegated only the plan's top-level OUs. These are the first component of each `domain.ou_tree`
    path, compared without case, in the plan's order, with the first spelling kept. On top of them comes the 1.4
    setup's own ACE on the domain head (`ms-DS-MachineAccountQuota`). The read-back is s8-read, in the password task
    after sshd comes back. It scans the domain partition and requires that newton-ops' SID holds explicit
    (non-inherited) ACEs on exactly those OUs plus the domain head, and on nothing else; otherwise the stage stops
    `readback_failed`. The scan does not cover the configuration and schema partitions, SYSVOL or the GPO files
    (SeBatchLogonRight lands in a GPO). It is unmeasured whether the 1.4 setup leaves another explicit ACE of
    newton-ops in the domain partition; if it does, the stage fails closed. An `ou_tree` with no OU is refused
    `schema` by the helper before anything runs.
57. K is shared by the build path and the 1.4 write path on DC1. In place of the passphrase prompt, the build variant
    of the write setup reads `C:\ProgramData\Newton\ad-build\key.hex` (64 lowercase hex characters) and installs it
    as the write path's `approval.key`. The setup's verdict checks that the fingerprint line it prints is
    `approval_fingerprint(K)` of the build key, and s8-read checks that `approval.key` equals `key.hex`. Stage 9
    deletes `key.hex` but not `approval.key`, so after the build the write path's K is still the one derived from the
    build passphrase. The maintainer's call: whether the owner re-keys the write path after the build (the 1.4 setup run again
    with a new passphrase).
58. The 1.4 output is unchanged by the template + fill refactor. Two goldens pin the bytes: `windows-write-1.4.ps1`
    and `windows-audit-1.3.ps1`, written before the refactor, with stub helper and collector files. The
    build variants differ in two places only, each pinned by a test: the key step reads K and asks for no
    passphrase, and no setup has a restart step of its own.
59. The bootstrap installs the stage 8 templates. Only DC1's bootstrap writes `s8-audit.tmpl.ps1` and
    `s8-ops.tmpl.ps1` into the install root. They are the generators' build templates
    (`setupgen.windows_template(build=True)`, `setupgen_write.windows_write_template(build=True)`), so the helper never
    holds a copy that can drift. The helper fills the generators' placeholders from the plan bytes. A test checks that
    the PowerShell fill equals the Python fill byte for byte. A template that is missing, or that keeps a placeholder
    the plan does not fill, is refused `schema` before anything runs. Stage 9 deletes both templates. A Newton
    upgraded between the bootstrap and stage 8 still runs the templates of the bootstrap's Newton. The write helper's
    bytes come from the runner, and their sha256 must be the plan's. (Superseded 2026-11-19, point 78: the bytes come
    from the file DC1's bootstrap installed.)
60. The order and the runs of stage 8. The run request carries the write helper as padded base64: at most 524288
    characters, only on a stage 8 run (393216 bytes on the runner's side). (Superseded 2026-11-19, point 78: no
    request carries it; the helper reads the installed `s8-write.ps1`.) A sha256 that is not the plan's stops it
    `write_helper_mismatch` before anything runs, and so does a stage 8 task still running from an earlier request
    (`out_of_order`). Then the 1.3 setup (newton-audit) runs first, and the 1.4 setup (newton-ops) second. Each is a
    filled script under `C:\NewtonBuild\ops` run in the password task, because the 1.4 setup backs up the PDC's policy.
    Each verdict requires four things, or the stage stops `op_failed`:
    - the script's sha256;
    - every step line of its generator, in order;
    - `setup exit 0`;
    - the setup's own key line, plus, for the 1.4 setup, its `sha256 write.ps1` line and its fingerprint line.
    Both setups write the same `C:\ProgramData\Newton\ad` directory, and each sets its own access list on it. The
    interplay of the two lists, and of the collector's and the write helper's files in it, is unmeasured.
61. The sshd restart is asynchronous. Neither build variant restarts sshd. After both setups, the key login registers
    a one-shot SYSTEM task, `NewtonBuild-sshd-restart`, and starts it, as stage 9 does. That task waits 10 s so the
    helper's answer can leave, runs `sshd -t`, restarts sshd, and writes `out\s8-sshd.txt` and `s8-sshd.rc` (0 only
    when the service runs under a new process id). The run answers `started`, at phase `s8_restart`. A status after
    that waits for the result file, for at most 900 s after the entry. A nonzero result stops `op_failed`, and so does
    no result past the bound. With a 0 result, s8-read runs and ends the stage `done` or `readback_failed`. Unmeasured:
    whether the restart inside the helper's own session drops that session (it should not, since the task runs after
    the answer), and how long sshd takes to come back.
62. Stage 8 is not on the status record path of point 18. A status at phase `s8_setup` (the session dropped while a
    setup ran) answers `started` and records nothing. A setup still running at the end of its 600 s wait stops the
    stage `op_failed` while the task may still finish. A later run of stage 8 is then refused `out_of_order` while
    the task runs, and `out_of_order` after it too under the same plan, since the stage is stopped. The owner restores the checkpoint. This
    fails closed, and the owner gets no resume.
63. s8-read reads stage 8 back in the password task once sshd is back. Each check stops `readback_failed`:
    - there is exactly one `Match User <netbios>\newton-ops` line and one for newton-audit;
    - `write_authorized_keys` and `authorized_keys` each equal `restrict <the plan's key>`;
    - the write helper on disk has the plan's sha256;
    - `approval.key` equals the build key;
    - sshd is `Running` and answers an `SSH-2.0-` banner on 127.0.0.1:22;
    - newton-audit's `tokenGroups` holds none of RIDs 498, 512, 516, 518, 519, 520, 521, 525, 526, 527 and none of
      builtin 544 and 548 to 552 (the privileged set of SPEC-1.4 section 5), and a groups line that was not read
      fails;
    - the delegation set of point 56 holds.

    It does not log in as either account over SSH. The design's "both logins answering" is a lab measurement
    (MEASURED-1.5), not a helper check.
64. The stage 9 cleanup removes the build block by its shape. It drops the bootstrap's marker line
    (`# newton-ad build`), the `Match User newton-build,…` line under it, and the indented lines after that, up to the
    first line that is not indented or is a `Match` line. Then it writes the file as LF, with no trailing blank lines.
    A configuration with no marker is kept as it is. When `sshd -t` refuses the result, the configuration from before
    the cleanup is written back and sshd restarts anyway. The keys file is still deleted, so the build login is gone
    either way. A test fails if the backup is restored. `sshd_config.bak-newton-build` itself stays on disk. The maintainer's
    call: whether stage 9 deletes it.
65. The runner reads stage 8 like any stage answered `started`. It polls status for at most 15 minutes from the run.
    The helper's restart bound is also 900 s, so either side may end it, and both stop. The fake helper of the runner
    tests now behaves like the real one: it requires the write helper on the 8 run (since 2026-11-19, point 78: the
    installed file, missing or changed refused as the helper refuses), compares its sha256, answers
    `started`, and ends `done` (or a read-back stop) on a later status. The one-DC and two-DC runs end at stage 10
    `done` with that stage 8.
66. The lab did not run on 2026-11-16. On apollo, free RAM was 4187 MB, below the 6 GB the lab rule needs, and vmdata
    was at 78.90%. BUILD1 (731) and BUILD2 (732) stayed stopped at `fresh-2026-11-13`. Stage 8 and the stage 9 change
    are therefore unmeasured, and every stage 8 output pinned in the tests is constructed: the shape the rendered ops
    print, not measured bytes (`tests/ad/build/fixtures/stage8/s8-read-constructed.txt`). MEASURED-1.5 "Stage 8 and 9
    on BUILD1, 2026-11-16" records the block and what to measure.
67. DC2 gets neither login. Stage 8 is in DC1's graph only (DC2's graph is 0, 1, 7, 9), the helper refuses stage 8
    on any role but dc1, and only DC1's bootstrap writes the stage 8 templates (point 59). So a two-DC build ends
    with newton-ops and newton-audit on DC1 only; DC2 has no write path and no audit login, and stage 10 reads
    through DC1. The Decided entry for open point 34 first said "each built DC"; it now says DC1, which is what the
    graphs and the code do. The maintainer's call: whether DC2 needs either login, which would add stage 8 to DC2's graph.
68. A runner started again after a stage token's EXP drops the token. The helper completes a stage 2 or 4 still in
    flight (rebooting or started in the journal) until EXP plus 15 minutes ("The helper"), but the runner reads a
    stage token only before its EXP (`run.py` `_stage_token`), so a runner restarted inside that grace window sends
    nothing of the stage, not even its status, and stops for a new approval of the stage. That fails closed: the new
    approval reuses the held checkpoint, and its token's status completes the stage from the journal with no second
    run (`test_a_runner_restarted_inside_a_tokens_post_boot_grace_waits_for_a_new_approval`). The cost is one more
    approval. The maintainer's call: whether the runner's status before the run may use the old token until EXP plus 900 s when
    the stage is in flight.
69. A stage 8 run can outlast its SSH session. The transport bounds one session at `TIMEOUT_S = 720` s, but the
    stage 8 run waits up to `TaskWaitSeconds = 600` s for each of its two setups, then registers the restart, so the
    helper may need about 1200 s. A run past 720 s stops the runner `connection_lost` while the helper may still go
    on to `s8_restart`, with stage 8 started in its journal. This fails closed: the helper refuses a second run of
    a stage in flight `out_of_order` (point 62), and a runner started again reads the stage's status before any run.
    Unmeasured: how long the two setups take on BUILD1.
    The maintainer's call: whether stage 8's session bound is raised above the helper's total wait, or the two setups split into
    two runs.
70. The OU names in s8-read's DNs are not escaped. The helper builds each delegated OU's DN as `OU=` + the plan's
    name with no RFC 4514 escaping. `plan.NAME_RE` (and the helper's `NamePattern`) allows a trailing space, which a
    DN must escape, so such an OU fails stage 8's read-back (`op_failed` or `readback_failed`) though the delegation
    may be right. There is no injection: the helper checks each name against `NamePattern` again and single-quotes
    it. This fails closed. The maintainer's call: escape DN special characters in the helper, or refuse a leading or trailing
    space in `NAME_RE` (which stage 5's names share).

The fixes of the part E review (2026-11-17, `newton/1.5-t8-runner`). Built the conservative way, not
decided:

71. A resume plan keeps the first plan's passwords (review finding 4). Before this fix, the approval of a resume plan
    derived the DSRM and admin passwords from the resume plan's own digest. A DC already promoted, or an admin
    already made by stage 5, keeps the passwords of the earlier plan, so the owner was shown passwords that the
    servers do not have. Two fixes were possible. The resume approval could show no passwords and say the old ones
    are still in force. Or the passwords could stay bound to the original plan. This fix binds them. A resume plan
    can be the first to run stage 2 (a stop before the promotion), stage 5 or stage 7. Under the first fix, the owner
    would never see the passwords those stages install. With one salt for the whole build, every approval shows the
    right values. What was built:
    - The plan model has a `secrets_from` field, a digest. A resume plan must carry it, and only a resume plan may.
      It is in the canonical bytes, so the owner's approval signs it. `plan.secrets_digest` gives the salt: the
      plan's own digest, or `secrets_from`.
    - `newton_ad_build_plan` fills the field from the plans on record. It takes the resumed plan's own
      `secrets_from`, or that plan's digest when it is the first plan. A value from the model that differs is
      refused.
    - The helper derives at stages 2, 5 and 7 from the same salt. It writes the salt as `secrets` in every journal
      entry. A resume plan whose `secrets_from` differs from the journal's salt is refused `plan_mismatch` before
      anything runs. For an entry without the field, the salt is that entry's digest.
    - The helper refuses `schema` for plan bytes that break the field's rule.

    Tests derive the secret on both sides: the helper's join on DC2 under a resume plan writes the DSRM secret that
    `newton-approve` prints for DC2. Stage 2 and stage 5 under a resume plan write the first plan's secrets. The
    runner tests' Python fake helper does not mirror the salt check. Not decided, and the maintainer's call:
    - whether a resume approval should print the passwords at all. It prints them again, labelled as the first
      plan's, which extends what point 52 says about re-approval;
    - whether the run id would be a better salt than a signed digest (it is not signed, so it was not used).
72. Each DC's DSRM password is shown (review finding 3). DC2's helper writes DC2's DSRM secret at the join from
    DC2's own K. DC1's install reads it on DC2 (point 24). The approval used to show only the DSRM derived from DC1's
    K. It now prints one `DSRM password of <device> (<role>)` per DC, each from that server's K and the build's salt,
    plus the admin password from DC1's K. A two-sided test runs DC2's join on the real helper with the K derived
    from the owner's passphrase, and finds the secret it writes on the line `newton-approve` prints for DC2.
    Unmeasured: DC2's actual DSRM login. The maintainer's call: whether DC2 should instead share DC1's DSRM password.
73. A stage 8 status can rejoin a read-back that an earlier status started (review finding 5). Before this fix, a
    session that dropped while s8-read ran in its task left the next status to start s8-read again. The task was
    still running, so the stage stopped `error`. Now, at `s8_restart`, once sshd's result passed:
    - while `NewtonBuild-s8-read` runs, the status answers `started` and records nothing;
    - once s8-read has ended, its result file is read, the task is removed, and the op is not run again.

    The run of stage 8 clears every s8-read file before its `started` entry, so a result file found later belongs to
    this run. A read that runs forever is bounded only by its task's 60-minute limit and the runner's 15-minute poll
    (point 65). Pwsh tests: one for a running read, one for an ended read that passed, one for an ended read that
    failed.
74. The ACE-count lines of s8-read are pinned as text (review finding 6). A test compares the rendered body's three
    lines that count newton-ops' explicit ACEs and print `ops explicit aces:`. The mutant `-gt 0` to `-gt 1` is
    killed by the whole stage 8 helper test file. The body is not run under pwsh with fakes of `Get-ADObject` and the
    security descriptor. Nothing of stage 8 is measured (point 66).
75. The bootstrap's passphrase prompt needs a console. Measured on BUILD1, 2026-11-18: `Read-Host -AsSecureString`
    hangs when the bootstrap runs over ssh with stdin as a pipe. The lab answered the two prompts over `ssh -tt`.
    Either the owner steps say "run it at the server's console or in an interactive ssh session", or the bootstrap
    reads the passphrase another way. Undecided.
    **Ruled by the maintainer, 2026-11-21: the owner steps say to run the bootstrap at the server's console or in an interactive
    ssh session (`ssh -tt`); no new passphrase path.** Built on newton/1.5-rulings-75-79: the bootstrap's header, a line
    printed right before the first `Read-Host`, and the `note` of `newton_ad_build_plan` in agent mode all say "at the
    server's console or in an interactive ssh session (ssh -tt)"; the golden render and `test_build_tools.py` pin the
    wording. The prompts are unchanged. Unmeasured on BUILD1: the new lines (the console behaviour is the 2026-11-18
    measurement).
76. A bootstrap re-run does not restart sshd when its configuration is unchanged. Measured on BUILD1, 2026-11-18:
    after a run stopped past step 7, the re-run found the block already in place (`sshdChanged` false), and sshd kept
    running with the old configuration until it was restarted by hand. Should step 11 always restart sshd, or restart
    it when the running service is older than the file? Undecided, not fixed.
    **Ruled by the maintainer, 2026-11-21: the bootstrap always restarts sshd, so a re-run after a stop past step 7 picks up the
    configuration.** Built on newton/1.5-rulings-75-79: the restart step (the last step: 10, or 11 on a Proxmox guest)
    registers the one-shot SYSTEM task on every run, whether or not `sshdChanged`; the configuration file is still
    written only when its bytes differ. `test_the_sshd_restart_does_not_depend_on_a_changed_configuration` pins it.
    Unmeasured on BUILD1: a re-run's restart.
77. The stage 7 read-back cannot pass as designed, even after the K17 wait (refines point 17). Measured on BUILD1 and
    BUILD2, 2026-11-18: DC1's `s7-read` polled for 30 minutes without forcing anything and ended `converged False`.
    (a) BDC2's inbound Schema NC from BDC1 kept "1 failure, last failure 03:03:06, 1908" from its boot throughout.
    The schema does not change, so nothing clears that row; every other NC read 0 failures both ways by 03:35Z.
    (b) `msDS-GenerationId` is not replicated, so BDC2's value read from DC1 is `absent`, while DC2 reads its own as
    present. The check of DC2's genid has to run on DC2 (DC2's status already reads it), not from DC1.
    (c) `dcdiag /s:BDC2` from DC1 fails `KccEvent`, `SystemLog` and `DFSREvent` with `0x6ba "The RPC server is
    unavailable."` (remote event log), plus `Replications` on row (a). `KccEvent` is not in the accepted list.
    Options for the maintainer: accept a failure older than the promotion's boot when a later success exists on the same NC, or
    force one `repadmin /replicate` of the Schema NC (a write); run DC2's dcdiag on DC2, or accept the remote
    event-log tests. Undecided. MEASURED-1.5 "Stage 8 on BUILD1, 2026-11-18" has the rows.
    **Ruled by the maintainer, 2026-11-21: (a) accept a replication failure row whose last-failure time is older than the
    promotion's boot time when a later success exists on the same NC; (b) read DC2's msDS-GenerationId on DC2 itself;
    (c) run DC2's dcdiag on DC2 itself, not `dcdiag /s:BDC2` from DC1; no extra writes (no forced `repadmin
    /replicate`).** Built on newton/1.5-rulings-75-79: (a) `s7-read` (the poll) and the read-back parser accept a row
    with failures only when its last failure is older than the read-back's start (`read-back started:` line of the
    output, DC1's local time as repadmin prints it) and some row of the same NC, either direction, shows 0 failures and
    a success after the failure; a failure not older, with no later success, or a read-back with no start line still
    fails `readback_failed`. The measured Schema row (`1,2026-11-18 03:03:06,2026-11-18 03:01:43,1908`, BDC1's inbound
    Schema row `03:16:13`) is the fixture `s7-read-measured-schema.txt`. DEVIATION to confirm: DC1 cannot read DC2's
    boot time and the measured failure (03:03:06) is 45 s newer than DC2's promotion boot (03:02:21), so a bound at the
    boot would not accept the measured row; the read-back's start, which follows DC2's boot and its done status, is
    the bound built. (b) the DC1 read-back no longer reads or checks DC2's genid; `s7-dc` (DC2's status after the
    promotion's boot) already read it on DC2 and its `generation_id` check stays. (c) the DC1 read-back runs `dcdiag`
    on DC1 only; `s7-dc` runs the full `dcdiag` on DC2 after the machine password's reset and nltest and checks it with
    the same lists (`dcdiag_dc2`), re-running it every 60 s for at most 480 s (`DiagWaitSeconds`, never past the
    token) while it does not pass; nothing is forced. Unmeasured on BUILD1: all of it. Open risk: DC2's own dcdiag
    `Replications` test may still fail on the Schema row of (a), which the rulings do not accept for dcdiag.
    **Ruled by the maintainer, 2026-11-21 (refined): the read-back accepts an old replication failure row only when all three
    hold: its last-failure time is older than the read-back's start time minus 2 minutes, the same naming context shows
    a success with 0 failures, and on at least one later poll that naming context still shows no new failure (the
    failure count and the last-failure time unchanged). Nothing is accepted on the first poll alone, and anything else
    still fails the read-back.** Built on newton/1.5-rulings-75-79: `s7-read`'s poll records a failing row on the poll
    that sees it and accepts it only on a later poll that shows it unchanged (a row that changes after it was recorded is
    never accepted); the op prints `old failures confirmed: True` and the parser accepts such a row only with that
    line, at least two polls, the two-minute window and the later success of the same NC. The measured read-back
    started at 03:08:01Z and the Schema row's last failure was at 03:03:06Z, 295 s earlier and so outside the window;
    its rows are the fixture `s7-read-measured-schema.txt`. Unmeasured on BUILD1: the confirming poll and the whole
    rule.
    **Ruled by the maintainer, 2026-11-22 (strict): a row that a poll of the read-back showed clean and that fails again is never
    accepted, even with the same failure count and last-failure time.** This is a fourth condition beside the three
    above. The op checks it, because the parser sees only the last poll's rows: while that row fails, no poll converges,
    so a run that ends with it failing ends `readback_failed`. A later poll that shows the row clean again (0 failures)
    can still converge, since no failure is accepted then. Built in 6fed4ee2; whether real repadmin output flaps like
    this is unmeasured.
78. The stage 8 run request cannot carry the write helper (contradicts the maintainer's decision R1 as built). Measured on BUILD1,
    2026-11-18: Windows PowerShell 5.1 under the server's OpenSSH reads at most 70 001 to 80 001 bytes of stdin and
    then hangs. cmd's `find` reads the same 190 000 bytes in full, so the transport delivers them. The stage 8 run is
    about 182 KB (the write helper is 135894 bytes, 181192 in base64). The runner waited 720 s and read
    `HelperUnavailable`, while the helper process was still reading stdin on BDC1 13 minutes later, and nothing of
    stage 8 ran. The transport was not changed. A proposal that keeps R1's guarantee: DC1's bootstrap installs the
    write helper's bytes as `s8-write.ps1` beside the stage 8 templates. At stage 8 the helper checks their sha256
    against the plan's `write_helper_sha256` and refuses `write_helper_mismatch` (or `schema` when the file is
    absent). No request carries the bytes, the stage 9 cleanup deletes the file, and the runner's check of the
    installed helper against the plan stays. Another option: send the request in chunks under 64 KB. Needs the maintainer's
    approval. Until then stage 8, the logins and their reads (point 66) stay unmeasured.
    **Ruled by the maintainer, 2026-11-19 (given as "open point 75, stage 8 transport"): the write helper is installed on the DC
    at bootstrap, at a fixed path with locked ACLs, and every stage that runs it checks its sha256 against the plan
    first; nothing large goes over stdin, and a missing or mismatched helper stops the stage with a plain next step,
    never a silent re-send.** Built on newton/1.5-s8-bootstrap: DC1's bootstrap writes `s8-write.ps1` in the install
    root (`bootstrap.WRITE_HELPER_FILE`, `Protect-NewtonPath`, SYSTEM and Administrators only) and prints its sha256;
    no request carries a `write_helper` field (one that does is refused `schema`); stage 8's run reads the file first
    and refuses `write_helper_missing` or `write_helper_mismatch` before any op, setup script or journal entry; the
    runner stops on either with Newton's own next step (run the bootstrap of that server again, then the build) and
    sends the run once; stage 9 deletes the file; the runner's check of the local Newton's helper stays. Unmeasured
    on BUILD1: the bootstrap's write on Server 2025 and stage 8 end to end.
79. Stage 0 needs a resolver that answers. Measured on BUILD1, 2026-11-18: on an isolated lab bridge with no DNS
    server, stage 0's DNS check did not pass. The lab ran an NXDOMAIN-only responder on the gateway and set the VM's
    DNS client to it before stage 0. Should the owner steps name this prep (DNS client set to a resolver that answers
    before stage 0), or should stage 0 accept "no resolver" on a lab build? Undecided.
    **Ruled by the maintainer, 2026-11-21: stage 0's DNS check stays strict; the owner steps name the prep: set the server's DNS
    client to a resolver that answers before stage 0.** Built on newton/1.5-rulings-75-79: the bootstrap's closing
    lines and the `note` of `newton_ad_build_plan` say it, and a stage 0 that stops `dns_unchecked` carries Newton's own
    next step (`run._dns_next_step`: "set the server's DNS client to a resolver that answers before stage 0 ... then
    run the build again"); tests pin the three. The check itself is unchanged. Unmeasured on BUILD1: the new texts.

One build at a time per state directory (2026-11-22). Built the conservative way, not decided:

80. Every MCP tool runs in a worker thread, so two `newton_ad_build_run` calls may overlap, where the event loop
    ran them one at a time. A resume plan is another plan id for the same servers, so the lock is of the whole state
    directory and not of one plan: one build at a time, whatever plan id it carries. The runner takes the lock
    (`.run.lock` in the state directory, opened without following a symlink) before the runner is built, and holds it
    until the run ends. Two reasons, and neither of them sends anything or writes the run state:
    - a second run that finds the lock held stops `run_in_progress`: it names no stage, and the owner's way on is to
      read `newton_ad_build_status` and call again;
    - a lock that cannot be opened or locked (a directory, a symlink, a state directory that cannot be written) stops
      `run_lock_unavailable`.

    The lock is of the state directory, which is the conservative reading: a lock per server set would let two builds
    of different servers run at the same time, and the run state of one plan is not the run state of another. Tested
    on fakes only: the fake transport, the fake adapters, a second file descriptor that holds the lock, and two
    overlapping calls in two threads. Unmeasured: a real build under the lock, and two MCP clients calling the tool at
    the same time. The lock excludes runs of this software, not a process of the same user that removes or renames the
    lock file. **Ruled by the maintainer, 2026-11-24: one lock for the state directory, one build at a time.** Eight lab
    builds on apollo ran under it.

The first apollo build on the merged tree (2026-11-23, plan 96fef4b0, on the merged 1.5 tree): stages 0 to 6 passed on
BUILD1 and BUILD2; stage 7 promoted DC2 (DomainRole 4, generation id, machine password reset, secure channel all
passed) and stopped. Three findings:

81. The journal lock and the status poll. DC2's post-boot op `s7-dc` ran inside a status request's session and held
    the journal lock from 01:59 to 02:12. The transport cut that session at 720 s (`HelperUnavailable`); the op kept
    running on DC2 and wrote its result (`readback_failed`) at 02:12:27. The next status, at 02:12:06, found the lock
    held and was refused `out_of_order`, which stopped the run. Fixed on newton/1.5-s7-fixes, no ruling needed: a held
    lock is the new code `journal_busy`; every status poll treats it as "not yet" until its own deadline; any other
    request refused `journal_busy` stops the run with that code and nothing is sent again. Known limit: the session
    timeout (720 s) is shorter than DC2's dcdiag wait (900 s, point 82), so a long `s7-dc` outlives its session and
    the runner reads its result from the journal afterwards. Point 83 takes `s7-dc` out of the session: it runs in
    its own task, and the status request waits at most the task wait. Measured once (this run); not changed.
82. DC2's own dcdiag. At its 480 s limit, `KnowsOfRoleHolders`, `RidManager` and `Replications` failed. Re-run as
    SYSTEM about 25 minutes after the promotion, the first two passed and `Replications` still failed, only on DC2's
    inbound Schema row from DC1 (`1,2026-11-24 01:59:32,2026-11-24 01:58:10,1908`, from DC2's first boot), the open
    risk point 77 named.
    **Ruled by the maintainer, 2026-11-23: (a) DC2's dcdiag may fail `Replications` only when every failing row of
    `repadmin /showrepl * /csv` passes the same four-part rule as the DC1 read-back (point 77: older than the start
    less 2 minutes, a later success on the same naming context, unchanged on a later poll, never seen clean and then
    failing); no writes; (b) DC2's dcdiag waits up to 15 minutes (900 s, never past the token).** Built on
    newton/1.5-s7-fixes: `s7-dc` prints its start line, polls repadmin on every pass with the rule copied exactly
    from `s7-read`, and prints `old failures confirmed`, the poll count and the last poll's rows; a failed
    `Replications` is accepted only on a pass that holds a failing row, every one of them accepted by the rule and
    recorded unchanged on an earlier pass, so the confirmation never outlives the failing row, and the parser accepts
    it only when the last poll's rows hold such a row (with all of those lines, `converged True` and
    `Get-NewtonReplicaRowsOk` passing). The wait is a hard limit (no pass starts once it is spent, and the sleep is the
    shorter of the poll and the time left) and it leaves the token the margin of one pass (180 s), so a pass that
    starts before the limit may end after it; the runner waits `REBOOT_TIMEOUT_S + S7_DC_DIAG_MAX_S +
    S7_DC_PASS_MARGIN_S` for DC2's `done`. The measured rows are the fixture
    `s7-dc-measured-schema.txt`. Unmeasured on BUILD1/BUILD2: all of it.
83. DC2's own read in a SYSTEM task. `s7-dc` runs in the helper's key login, which holds no network credentials:
    dcdiag's `KnowsOfRoleHolders` and `RidManager` fail with `[BDC1] DsBindWithSpnEx() failed with error 5` for the
    whole 900 s wait (the lab run of 2026-11-23, real Server 2025). The same tests on DC2 run as
    NT AUTHORITY\SYSTEM (a one-shot scheduled task) and pass; only the expected old Schema row fails
    `Replications`. DC1's `s7-read` avoids this by running in a password task, but on DC2 after the promotion that
    stored local password is not the domain account's.
    **Ruled by the maintainer, 2026-11-23: DC2's read-only check (`s7-dc`: its repadmin and dcdiag, and the rest
    of the op as it is) runs in a ONE-SHOT task as NT AUTHORITY\SYSTEM (DC2's machine account), registered for that
    one run and removed after.**
    Built on newton/1.5-s7-fixes-r2: a SYSTEM variant of the task runner (`Invoke-NewtonSystemTask` beside
    `Invoke-NewtonPasswordTask`, the same contract, the same outcomes, the same op/out/result files, the same
    disable-read-unregister handling, and the same code shared with the password task), registered with
    `New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest` and with
    no password; the password task's own registration is unchanged. The stage 7 post-boot path runs `s7-dc` in that
    task and waits at most the usual task wait, so the status request does not hold the session (and the journal
    lock) for the whole op: a status while the task runs answers the stage in flight (the same way stage 7's DC1
    `s7-read` is answered while its task runs), starts no second task, and a later status reads the op's result
    file and completes the stage with today's verdict (`Get-NewtonStage7DcVerdict`, unchanged); a task that never
    starts, or that ends without a result file, stops the stage as the other task ops do. The op's body, the
    old-row rule, the 900 s wait and its token margin, the runner's bounds and the codes are unchanged.
    Unmeasured on BUILD1/BUILD2: all of it.

The stage 10 audit of the built domain (lab run 5, 2026-11-24, real Server 2025, stages 0 to 9 passed):

84. The newton-audit read of the built domain found AD-A-01/06/09 (the built-in Administrator is enabled, is not in
    Protected Users and may be delegated; the lab plan chose the baseline option `administrator = random-password`),
    AD-A-03 (owner-admin is in Domain Admins), AD-A-17 (the newton-ops password never expires), AD-A-21 (owner-admin
    must change its password at next logon), AD-A-44 (`ms-DS-MachineAccountQuota` of the domain head is 10) and
    AD-A-46 (no computer account carries `msLAPS-PasswordExpirationTime`: stage 4 extends the schema and sets the SELF
    ACEs on OU=Domain Controllers, but nothing turns Windows LAPS on).
    **Ruled by the maintainer, 2026-11-24: fix the machine account quota, LAPS for the DCs and owner-admin's delegation
    in the build; disable the built-in Administrator through the baseline option; accept AD-A-03, AD-A-17, AD-A-21 and
    the audit account's access-denied unknowns with reason codes.**
    Built on newton/1.5-s7-fixes-r2: stage 5 sets `ms-DS-MachineAccountQuota` of the domain head to 0 (`Set-ADObject`,
    the domain named by its SID) and reads the quota back before and after the write, so the new check
    `machine_account_quota` proves 0 and names both; stage 5 sets `AccountNotDelegated` on the owner admin and reads
    its `userAccountControl` back, so the new check `owner_admin_not_delegated` proves the NOT_DELEGATED bit
    (0x100000); the DC baseline GPO sets the three values of the Windows LAPS policy under
    `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS` (`BackupDirectory` = 2, Active Directory only,
    `ADPasswordEncryptionEnabled` = 1 and `ADBackupDSRMPassword` = 1, each a DWORD), stage 6's read runs
    `Invoke-LapsPolicyProcessing` after the refresh and reads the computer object of DC1 back, so the new check `laps`
    proves `msLAPS-PasswordExpirationTime` (or the encrypted DSRM attribute) is there; the built-in Administrator is
    disabled through the baseline option `administrator = "disabled"`, and with that option alone stage 5 also adds the
    account of RID 500 to Protected Users (RID 525) and reads the membership back, so the new check
    `builtin_administrator_protected_users` proves it (AD-A-06 and AD-A-09 skip a member of Protected Users); with the
    option `random-password` nothing of that changes. The checks are unchanged.
    The three LAPS values are named by the page of Microsoft Learn
    (https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings, read 2026-11-24):
    `BackupDirectory` = 2 ("Back up the password to Windows Server Active Directory only"), `ADPasswordEncryptionEnabled`
    = 1 (the encryption of the password in the directory) and `ADBackupDSRMPassword` = 1 (the backup of the DSRM account
    password of the domain controller, which is ignored unless the encryption is on). That page states that the
    encryption needs the domain functional level 2016 or later, so the plan and the helper refuse a domain below that
    level and the refusal says why (`free_text` in the plan, `schema` in the helper); the level of the plan is 10
    (Windows Server 2025, measured), so the requirement holds.
    The baseline file holds the three LAPS values with `security_template = false`, so the export of the security policy
    (the area secedit exports, which never holds the LAPS policy) is asked for the values of the template only and the
    read of the registry proves the LAPS values.
    Unmeasured on BUILD1/BUILD2: all of it.

## Out of scope

Brownfield domains, raising a level, more than two DCs, child domains, AD CS, DHCP, file servers, Entra Connect,
trusts, and building on Samba.

## The lab (apollo; the maintainer, 2026-11-13)

supernova is not available for 1.5, so the build lab is on apollo (Proxmox). This replaces the nested lab on
supernova that task 0 measured in; those measurements stand.
- New Server 2025 eval VMs on apollo for the builds, made for 1.5, with `vmgenid` and `agent: 1`, fixed RAM, at most
  4 vCPU, the same disk and RAM limits as before. No other VM on apollo is touched.
- Checkpoints are Proxmox snapshots, taken with a scoped API token whose role holds only `VM.Snapshot` and `VM.Audit`
  on the build VMs (the Proxmox method above), with an expiry; it is deleted after the lab work, or it expires.
- The AD lab's DC2s (722 and 724) are off between runs.
- Before any VM starts: free RAM and the `vmdata` thin pool are checked, and the pool never passes 85%.
- Every build VM is off after a run.

## Tests

- Unit: the plan grammar and bytes; a request whose plan bytes differ by one value is refused even with a valid token
  for the original; per-server tokens; the stage digest including the checkpoint id; the journal under pwsh (seq,
  CreateNew, resume chain, boot-time rule, the EXP+15 min rule); golden renders of every template, fed raw hostile
  values directly (not only through the grammar); the checkpoint adapters against fakes pinned to measured bytes.
- Live, in the nested lab: the one-DC build; the deviations (a wrong token, a changed plan byte, out of order, a run
  killed mid-stage then resumed, a failed checkpoint); the two-DC build; a rollback of a DC checkpoint showing the
  invocationID reset (2170 and 1109); restoring a workgroup checkpoint showing a workgroup server; then promote again
  and finish with a clean stage 10.
