# Newton 1.5 plan: AD build mode

**Goal:** Newton builds a hardened one- or two-DC Windows Server 2025 forest from one approved plan, with a fresh
owner yes and a read-back checkpoint before each irreversible stage. Design: `DESIGN-1.5.md` revision 2 (approved in
revision 1; revision 2 answers `REVIEW-1.5.md`; stage 7 is option B, the maintainer, 2026-11-11).

## Constraints

- Branch `newton/1.5-ad-build`; each packet in its own worktree off it; merge to main, and push public, once task 10
  and the cross-family review pass (the maintainer, 2026-11-11: no separate yes needed).
- Python 3.12 (the `mcp` venv); the helper is Windows PowerShell 5.1, tested under pwsh 7 like `write.ps1`.
- Tokens: `newton_mcp.approve.approval_token(K, digest, nbf, exp)` only; one K per server from `derive_k(passphrase,
  device)`; a token per server.
- Plan header line `newton-ad-build-v1`; stage digest header `newton-ad-build-stage-v1` with `plan=`, `stage=`,
  `checkpoint=` lines; ASCII; LF; sorted pairs. Secrets: HKDF-SHA256(K, salt=`plan.secrets_digest(plan)`,
  info=`newton-ad-build-dsrm-v1` or `newton-ad-build-admin-v1`): the salt is the digest of the build's first plan,
  which a resume plan carries as `secrets_from` in its signed bytes (DESIGN-1.5 "Secrets", open points 71 and 72).
- Reversible-token window 6 hours; each irreversible-stage token 30 minutes.
- Stage ids `0` to `10` exactly as in the design table; per-server graphs DC1 `0 1 2 3 4 5 6 7 8 9 10`, DC2
  `0 1 7 9`; `7` exists only when the plan has two servers.
- Baseline file `mcp/newton_mcp/ad/build/baseline-2026.11.toml`.
- Lab (the maintainer, 2026-11-13; DESIGN-1.5 "The lab"): apollo. New Server 2025 eval build VMs, fixed RAM, at most 4 vCPU,
  off after every run; Proxmox snapshots through a scoped API token limited to the build VMs; the AD lab DC2s 722 and
  724 off between runs; `vmdata` never past 85%. Task 0 measured in the nested lab on supernova, and those
  measurements stand.
- Ruled by the maintainer, 2026-11-13: stage 9 runs under the plan token (never a stage token); `verify(server_cfg, cp, kind, *, stage,
  not_before)`, where `not_before` (task 7 triage) is passed on every call with no default: the later of the plan
  approval's NBF and the previous stage's completion from the helper's journal (DESIGN-1.5 "Checkpoints"); a stage
  approval needs an unexpired plan approval.
- `skills/` and `SKILL.md` are protected: the skill text (task 9) needs the maintainer's approval on the exact diff.

## File map

| Path | Responsibility |
|---|---|
| `mcp/newton_mcp/ad/build/plan.py` | input grammar, `canonical_bytes`, `digest`, `stage_digest`, `plan_build` |
| `mcp/newton_mcp/ad/build/baseline.py` + `baseline-2026.11.toml` | load and validate the baseline; option choice |
| `mcp/newton_mcp/ad/build/bootstrap.py` | render the per-server bootstrap `.ps1` |
| `mcp/newton_mcp/ad/build/helper/build.ps1` | forced-command helper: token check, journal, order, the stage templates |
| `mcp/newton_mcp/ad/build/checkpoint.py` + `helper/hv-checkpoint.ps1` | Hyper-V, Proxmox and wbadmin adapters |
| `mcp/newton_mcp/ad/build/run.py` | drive the stages, reconnect after reboots, stop on deviation, receipts |
| `mcp/newton_mcp/ad/build/stage_token.py` | which token covers each stage (the plan token, a stage token, or the plan token for stage 9) |
| `mcp/newton_mcp/ad/build/transport.py` | the ssh transport to the build helper, request and answer shapes, the journal's completions and `not_before` |
| `mcp/newton_mcp/ad/build/config.py` | the owner's `ad-build.toml`: helper logins, checkpoint adapter targets, the stage 10 audit login |
| `mcp/newton_mcp/ad/build/acceptance.py` | stage 10, the acceptance read through the 1.3 newton-audit collector |
| `mcp/newton_mcp/ad/build/tools.py` | the MCP tools' bodies (`newton_ad_build_plan`, `_run`, `_status`) |
| `mcp/newton_mcp/approve.py` | `approve_ad_build`, `approve_ad_build_stage` |
| `mcp/newton_mcp/server.py` | MCP tools `newton_ad_build_plan`, `newton_ad_build_run`, `newton_ad_build_status` |
| `mcp/tests/ad/build/` | every test below |
| `docs/proposals/ad/MEASURED-1.5.md` | task 0 measurements, the bytes the fakes are pinned to |
| `docs/proposals/ad/REVIEW-1.5.md` | the cold review and what each finding changed |

## Tasks

**0. Lab and measurements (main session, lab work only; gates task 3 onward). DONE 2026-11-11: `MEASURED-1.5.md` (open: the Hyper-V first-boot GenID case).**
Build NLAB-HVHOST (nested Hyper-V), BUILD1 and BUILD2 inside it, then NLAB-PVE on its own. Measure and record:
nested virtualisation runs with supernova's VBS on; a local `newton-build` key login survives the first promotion and
its forced command still runs; which of New-GPO, Enable-ADOptionalFeature and Update-LapsADSchema fail over the S4U
key login and pass in a password session; the exact output of Checkpoint-VM / Get-VMSnapshot through a forced command,
of the Proxmox snapshot API with a scoped token, and of `wbadmin get versions`. Done when MEASURED-1.5.md holds each
answer with the command that produced it. If the account does not survive promotion, stop and revise the design with
the maintainer.

**1. Plan model.** `plan_build(inputs: Mapping) -> dict` (raises `BuildPlanRefused(code)`),
`canonical_bytes(plan) -> bytes`, `digest(plan) -> str`, `stage_digest(plan_digest, stage, checkpoint_id) -> str`,
`stage_graph(plan, server) -> tuple[str, ...]`, `derive_secret(k_hex, plan_digest, info) -> str`.
Tests `test_build_plan.py`: a golden plan's bytes and digest pinned; every field changes the digest; `stage_digest`
pinned for a pinned digest, stage `"2"` and a checkpoint id; graphs exactly as in Constraints; refusals `bad_dns_name`,
`bad_netbios` (16+ chars, dot), `bad_ip`, `duplicate_ip`, `unknown_baseline_option`, `free_text`,
`two_servers_same_name`, `proxmox_without_vmgenid`, `proxmox_without_agent`; a resumed plan carries `resume_from` and
`start_stage`; `derive_secret` pinned and meets the complexity rules. Verify:
`cd mcp && .venv/bin/python -m pytest tests/ad/build/test_build_plan.py -q`.

**2. Approval.** `approve_ad_build(plan_id) -> int` prints every field, derives each server's K, prints the DSRM and
admin passwords once, and writes a plan token per server. `approve_ad_build_stage(plan_id, stage) -> int` refuses
when the plan approval has expired (now at or past its EXP; `expired`, naming the re-approval command; the maintainer,
2026-11-13), calls the checkpoint adapter's `verify(server_cfg, cp, kind, stage=stage)` itself, prints the checkpoint
and the restore cost, and writes a stage token per server; stage 9 gets no stage token (the plan token covers it).
Tests `test_build_approve.py`: every plan field printed; one token per server and each verifies only with its own K;
the stage token verifies against `stage_digest` with the verified checkpoint id; refused when `verify` fails even if
the runner's state says `stopped_for_approval`; the adapter receives the stage; refused past the plan approval's EXP;
the passwords appear in the terminal output and nowhere in the state directory.

**3. Helper core.** `build.ps1` reads one JSON request on stdin: `{run, plan, stage, action, token, nbf, exp}` where
`plan` is the canonical bytes (base64) and `action` is `run`, `status` or `checkpoint`. Answers `{ok, status, code,
checks}`. Refusal codes: `bad_token`, `expired`, `out_of_order`, `already_done`, `plan_mismatch`, `schema`. Journal
`<run>.<seq>.json`, CreateNew, Flush(true), entries with stage, state, digest, checkpoint id, boot time. Tests
`test_build_helper.py` under pwsh with a fake stage table: each refusal; one changed plan byte with the original's
token is `bad_token`; `already_done` on a repeat; `plan_mismatch` for another digest, accepted for a valid
`resume_from` chain; `status` before the boot time advances keeps `rebooting`; post-boot completion refused after EXP
plus 15 minutes; after a dropped connection, a status request records the stage's terminal entry from the op's own
`.rc` result file (the status record path, DESIGN-1.5 "The build account after promotion"), only under the plan the stage
started under, never running an op, until EXP plus 15 minutes and past it as the design says (a task still running is
refused `expired`, no `.rc` stops `grace_passed`).

**4. Bootstrap.** `render_bootstrap(plan, server, k_hex) -> str`. Tests `test_build_bootstrap.py`: golden render;
`Match User newton-build,<netbios>\newton-build` in lower case ahead of the administrators block; `PasswordAuthentication
no` and `KbdInteractiveAuthentication no`; sshd started once before its config is read; the config backed up; the
firewall rule `-Profile Any`; the Proxmox variant installs vioserial and QEMU-GA; K and pw.bin ACL SYSTEM and
Administrators; raw hostile values fed to the renderer directly stay inside escaped single-quoted literals.

**5. Stages 0 to 4.** Starts with one measurement on BUILD1: stage 2's post-boot writes (`Add-ADGroupMember`, the
second reboot, the `msDS-GenerationId` read) through the password task. Then the templates. Tests
`test_build_stages_0_4.py`: golden renders; stage 0 refusals `ip_mismatch`, `clock_skew`, `domain_exists`,
`agent_missing`; stage 1 never touches the IP; stage 2 uses `-NoRebootOnCompletion`, adds the three groups after the
first boot and does not finish until `msDS-GenerationId` is present; stage 4 removes Enterprise and Schema Admins,
then reboots DC1 and, after the boot, reads newton-build's groups back in the directory and in the S4U key login's
token, stopping `privileged_groups_remain` if either still holds 519 or 518 (the maintainer, 2026-11-13);
read-backs against measured fixtures.

**6. Baseline, stages 5 and 6.** `load_baseline(version) -> Baseline`. Tests `test_build_baseline.py`: every entry
has a `learn.microsoft.com` source or a CIS number with no copied text; an unknown option refused; stage 5 golden
renders with raw hostile OU, group and account names; the built-in Administrator handled per its option; stage 6
golden renders per GPO; secedit read-back parsing against a measured export; secrets reach the task only through the
DPAPI file (no secret in any rendered command line). Resume (DESIGN-1.5 "Deviation and resume"; F1 of the stage 4
triage, bug hunt R1): a stage 3 or 4 stopped after its write (`grace_passed`, `error`, a failed
read-back), resumed, reads its state first (`s3-state`, `s4-state`) and ends `done` with no second
`Enable-ADOptionalFeature` or `Update-LapsADSchema`; the measured before-state runs the op; any other state stops
`readback_failed` with no write; a resume while a read still runs is `out_of_order`. The owner's admin account is never
a built-in name, and stage 5 adds only an account it made (its description marker) to Domain Admins and Protected Users.

**7. Checkpoint adapters.** Starts by capturing raw bytes on the apollo lab (the maintainer, 2026-11-13): `repadmin
/showbackup`, `wbadmin get versions` after `-allCritical` and after `systemstatebackup`, a Proxmox task log of the
scoped token with a failed freeze if one can be forced; the Hyper-V bytes are the ones task 0 measured.
`checkpoint(server_cfg, kind) -> {"name", "id"}`, `verify(server_cfg, cp, kind, *, stage) -> bool` for `workgroup` and
`dc`, per method `hyperv`, `proxmox`, `wbadmin`. Tests `test_build_checkpoint.py` against those bytes: an unverified
checkpoint stops the run with `checkpoint_unverified`; a DC checkpoint without `msDS-GenerationId` is unverified; a
Proxmox task with a warning between freeze and thaw, or a non-OK exitstatus, is unverified; `hv-checkpoint.ps1`
refuses a VM outside its allowlist and lists one snapshot as a JSON array; a wbadmin system-state version is refused
for stages 2 and 7 and accepted for 3, 4 and 6 (the stage rule is in `checkpoint.py` already, from the 2026-11-13
rulings; the read of `wbadmin get versions` is not).

**8. Stages 7 to 10, runner, MCP tools.** `run_build(plan_id) -> dict` through the fake transport. Stage 7 is option B
(the maintainer, 2026-11-11): djoin and WinRM from DC1, measured first on BUILD1 and BUILD2. Tests `test_build_run.py`: one-DC and two-DC runs end at stage 10 `done`; each irreversible stage stops at
`stopped_for_approval`; `connection_lost` and `reboot_timeout` (15 minutes); no domain credential in any request
Newton sends (grep every recorded request and the state directory); cleanup order DC2 then DC1 with the account
deleted last; stage 10 runs through the read-only newton-audit login (the 1.3 collector; the maintainer, R2, 2026-11-15)
and stops on a finding outside the accepted list.
`newton_ad_build_plan(..., mode="scripts")` (the default) returns the plan and its stage list and no bootstrap;
the owner-run stage scripts are not built (DESIGN-1.5, task 8 open point 15); `mode="agent"` is build mode.

**9. Skill text.** The interview, choosing options, the script-tier fallback, NTLM restrict as a later judgement call,
and the owner's after-build steps (remove the Hyper-V login or the Proxmox token).

**10. Live.** In the apollo lab (the maintainer, 2026-11-13: new Server 2025 eval build VMs, Proxmox snapshots through the
scoped token, DC2s 722 and 724 off between runs): the one-DC build; the deviations (a wrong token, a changed plan byte, out of order,
killed mid-stage then resumed, a failed checkpoint); the two-DC build; a DC checkpoint rollback showing 2170 and
1109; a workgroup checkpoint restore showing a workgroup server; promote again and finish with a clean stage 10. Then
a cross-family review of the branch.

## Review focus

1. A token that expires while a stage is rebooting: post-boot completion allowed only until EXP plus 15 minutes
   (task 3 test).
2. Newton killed during a rebooting stage, then started again: status resumes from the journal (task 3 and 8 tests).
3. The plan's DNS name already answers on the network: stage 0 refuses with `domain_exists` (task 5 test).
4. Hostile OU, group and account names reaching a template: fed raw to the renderers (task 4 and 6 tests).
5. Two runs against one server at once: the second answers `plan_mismatch` or `out_of_order` (task 3 test).
