# AD 1.5 cold review, 2026-11-11

Reviewer: Gemini through `agy` in plan mode (read-only), one bounded bundle: DESIGN, PLAN and MEASURED revision 1,
the lab probe scripts, and the Proxmox raw outputs; told to attack, not to praise. codex was out of quota until
2026-11-15 and GLM until 09:31. Each finding was checked against the documents and the session's evidence by Claude
(Opus), the reviewer of record.

| # | Finding | Verdict | Disposition (revision 2) |
|---|---|---|---|
| 1 | The token signs the plan digest, but the helper took `params` beside it, so a compromised runner could change parameters | valid, critical | Every request carries the full plan bytes; the helper recomputes the digest and reads its parameters from them |
| 2 | Releasing newton-build's password to Newton in stage 7 exposes a Domain/Enterprise/Schema Admin credential; with password auth on, a UPN login skips the `Match User` block; rotating it broke DC2's later stages | valid, critical | Release removed. Stage 7 is option A (script tier) or B (djoin plus WinRM from DC1), OPEN for the maintainer. Password auth off in the bootstrap. Enterprise and Schema Admins removed at the end of stage 4 |
| 3 | A per-server K makes one token fail on the other server | valid | Tokens per server; `newton-approve` derives every server's K |
| 4 | DC2's stage sequence was undefined (no stage 1, out-of-order refusals, stage 7 needs two DC1 calls), and stage 10 deleted the shared account before DC2's cleanup | valid | Per-server stage graphs; cleanup is DC2 first, the domain account deleted last by a SYSTEM task on DC1; acceptance moved after cleanup |
| 5 | Workgroup checkpoints cannot pass DC read-backs; a system-state backup cannot undo a promotion; no path for the helper to take a wbadmin backup | valid | Two checkpoint kinds; `-allCritical` bare-metal backup before stages 2 and 7, system state only before 3, 4, 6; a `checkpoint` action in the helper |
| 6 | `msDS-GenerationId` not checked for DC2 nor in the tests; the Hyper-V first-boot case unmeasured | valid | Stage 2 and stage 7 reboot until the attribute is present, read back on both DCs; DC checkpoint read-back requires it. The Hyper-V first-boot case stays open in MEASURED |
| 7 | Journal name collisions with CreateNew; resume deadlock between `plan_mismatch` and `out_of_order`; a dropped SSH session leaves the journal unwritten while the task runs | valid | `<run>.<seq>.json`; `resume_from` and `start_stage` in the signed plan; the scheduled task writes its own terminal entry |
| 8 | `hv-checkpoint.ps1` serves one VM, has no token, and PowerShell 5.1 turns a one-item list into an object | valid | An allowlist of VMs, `create <vm> <name>`, `ConvertTo-Json -InputObject @(...)`; the owner removes the login after the build (Newton cannot) |
| 9.1 | `gpoedit` swallows errors and reports `ok` | valid about the flag, not about the counts | Counts came from the step text (a failure shows `FAIL@`); caveat added to MEASURED |
| 9.2 | Server 2025's base schema already holds LAPS, so the probe proved nothing | wrong | Measured: schema 91 without the update has no `msLAPS-*` attribute; added to MEASURED |
| 9.3 | Recycle Bin failed in the task with the groups present; the design ignored the reboot advice | valid | Stage 2 adds the groups, then reboots (also for `msDS-GenerationId`) |
| 9.4 | The probe's task wait could exit before the task started | valid for the probe | The helper waits for `LastTaskResult` and the journal entry |
| 9.5 | Stage 2's post-boot writes over S4U were never measured | valid | Task 5 starts with that measurement on BUILD1 |
| 10.1 | The token can leave the DC off: a rollback to a `vmstate=0` snapshot stopped VM 100 | valid; my "cannot power the DC off" was wrong | Corrected in MEASURED and DESIGN |
| 10.2 | The post-rollback vmgenid is not in measure.sh's output | evidence was in a follow-up command, not the bundle | MEASURED now names the command |
| 10.3 | The token expiry was never set in the scripts | set in the same follow-up (`expire: 1794381102`) | MEASURED now names the command |
| 10.4 | Freeze and thaw lines appear even when the freeze fails | plausible, unmeasured | The read-back also needs `exitstatus OK` and no warning between the lines |
| 10.5 | The token cannot delete itself | valid | The owner deletes it, or it expires; the final report says so |
| 11 | No delivery path for the DSRM and admin passwords; a task command line would log them | valid | Both derived from K with HKDF on the DC and in `newton-approve`; passed to the task through a DPAPI file |
| 12 | The stage token did not bind the checkpoint, and `newton-approve` trusted the runner's state | valid | The stage digest includes the checkpoint id; `approve_ad_build_stage` verifies the checkpoint itself |
| 13 | Stage 1 re-set the IP in the SSH session | valid | Stage 0 requires the IP to equal the plan's; stage 1 leaves it alone |
| 14 | Promotion reboots before the journal is written; a status poll before the reboot; privileged post-boot writes under an expired token | valid | `-NoRebootOnCompletion`, the boot-time rule, EXP plus 15 minutes |
| 15 | The audit ran while newton-build was still a privileged account; the built-in Administrator was untouched | valid | Acceptance after cleanup, through newton-ops; stage 5 handles the built-in Administrator |
| 16 | Stage 6 is not reversible (security settings tattoo) | valid | Stage 6 is irreversible with a checkpoint and a stage token; stage 9 is `final` |
| 17 | Tests that pass while the requirement is broken (the `Match User` form, sshd_config missing on a fresh server, the firewall profile, Proxmox drivers, `domain_exists`, the clock check, hostile values only through the grammar, no pinned Hyper-V bytes, the restore-then-audit order) | valid | Bootstrap and tests updated in DESIGN and PLAN; raw bytes for the Hyper-V fakes are captured at the start of task 7 |
