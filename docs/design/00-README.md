# NEWTON — Design Package v0.1

> **NEWTON**: an AI "senior network engineer." An MCP server plus Agent Skills that let an agent
> (Claude Code, OpenCode, …) **read, plan, change, verify, and roll back** network device
> configuration safely. First platform: **OpenWrt 25.12** on a physical lab router + a virtual twin.

| | |
|---|---|
| Date | 2026-10-06 |
| Owner | The maintainer |
| Status | DRAFT v0.1 — research-backed; nothing is "done" until its acceptance tests pass |
| Audience | Coding agents (primary), the maintainer (reviewer/approver) |

---

## How to use this package

1. These files live in the NEWTON repo at `docs/design/`. `docs/design/AGENTS.md` holds the rules for coding agents; copy it to the repo root if your agent reads its rules from there.
2. Read `docs/design/AGENTS.md` first (any coding agent), then the current release in `docs/ROADMAP.md`.
3. A phase is complete **only** when its acceptance tests (IDs in `09-LAB-AND-TEST-STRATEGY.md`)
   pass — unit/contract in CI, twin/HIL in the lab.
4. Design changes go through an ADR in `11-ADRS.md`. Agents must not silently diverge from these docs.
5. When something is verified in the lab, record it in `12-VERIFICATION-LEDGER.md` (and later in the
   machine-readable Verified Facts Ledger, see `08`).

### Design phases
The design is ordered so that **no write path exists before the controls that make it safe**: read-only, then the safety kernel, then transactions. The design documents refer to these early phases as P0 to P10; the released and planned releases are in `docs/ROADMAP.md`.


---

## Status tags (used in every doc)

| Tag | Meaning | Rule for code |
|---|---|---|
| **[V-nn]** | Verified by research on 2026-10-06; source in `12-VERIFICATION-LEDGER.md` | Code may depend on it (still covered by tests) |
| **[LVR-nn]** | Lab Verification Required — likely, but unproven on *our* target | Code depending on it must ship **with the test that proves it**; close the LVR when that test passes on the DUT |
| **[A-nn]** | Assumption — the maintainer must confirm | Don't build irreversible structure on it |
| **[ADR-nnn]** | Architecture decision | Change only via a new/superseding ADR |
| **[OPEN]** | Undecided | Decide before the phase that needs it |

---

## Reading order

- **The maintainer:** 02 → 01 → 03 → 04 → the design phases above
- **Coding agents:** `docs/design/AGENTS.md` → `docs/ROADMAP.md` → 03 → 04 → the spec for that phase
  (05/06/07/08/09) → 11 → 12

## Files

| File | What it answers |
|---|---|
| `01-PRIOR-ART.md` | Has someone built this? What exists, what to borrow, build-vs-adopt |
| `02-REALITY-CHECK-AND-SCOPE.md` | Why "train it on all the docs + add safeguards" isn't the hard part; goals, non-goals, metrics |
| `03-ARCHITECTURE.md` | Components, transaction state machine, data model, deployment, repo layout |
| `04-SECURITY-AND-SAFETY-MODEL.md` | Threat model, trust boundaries, untrusted data, secrets, leash rules, approvals, audit |
| `05-DEVICE-ABSTRACTION-AND-VENDOR-STRATEGY.md` | Adapter contract, capability flags, tiers, platform certification |
| `06-OPENWRT-ADAPTER-SPEC.md` | First platform in detail: access paths, ACLs, apply/rollback, effect checks, linter, recovery |
| `07-MCP-AND-SKILLS-INTERFACE.md` | MCP tool catalog, schemas, error model, approvals, skill packaging, harness config |
| `08-KNOWLEDGE-LAYER.md` | Skills, Verified Facts Ledger, doc-claim → lab-test loop, RAG rules, skill drafts |
| `09-LAB-AND-TEST-STRATEGY.md` | Lab topology, test pyramid, chaos tests, red-team corpus, NEWTON-Bench |
| `11-ADRS.md` | Architecture decision records ADR-001…ADR-012 |
| `12-VERIFICATION-LEDGER.md` | Every researched fact + source URL; LVR, assumption, and open-question registers |
| `AGENTS.md` | Drop-in repo-root instructions for coding agents |

---

## The ten decisions that matter most

1. **The LLM proposes; deterministic code disposes.** No raw shell to devices by default. [ADR-003]
2. **Every write is a transaction with a device-side dead-man rollback.** A rollback timer that lives
   only in the controller or the agent dies with them. [ADR-004]
3. **Verify the effect, not the write.** Read-back ≠ applied ≠ effective. [ADR-010]
4. **Device output is hostile input.** DHCP hostnames, SSIDs, LLDP, logs can carry prompt injection.
   Authorization lives in code, never in prompts. [04]
5. **Secrets never flow to the model.** Placeholders that can only mean "unchanged." [ADR-007]
6. **Approvals are human, out-of-band, and bound to the exact plan hash.** The agent has no approve
   tool and cannot reach the approval path. [ADR-008]
7. **The agent can never edit its own leash** (its access path, ACLs, keys, profile, mgmt interface). [04]
8. **Multi-vendor scales by certification tiers in a virtual lab**, not by ingesting manuals. [ADR-009]
9. **Docs are claims; the Verified Facts Ledger is lab-proven behavior.** [08]
10. **MCP server (capabilities) + Agent Skills (knowledge)** — both open standards, so any harness can
    drive NEWTON. [ADR-001]

---

## Glossary

| Term | Meaning |
|---|---|
| DUT | Device under test (the physical lab router) |
| Twin | Virtual replica (x86-64 OpenWrt VM / containerlab node) used to pre-test a change |
| OOB | Out-of-band access (serial console, power control) that survives a broken data plane |
| LKG | Last-known-good configuration snapshot |
| Plan | A proposed change: ops + rendered diff + base-config hash + risk + policy verdict; immutable, hashed |
| Txn | Execution of a plan; has a state machine and an evidence record |
| Profile | Policy binding on a device: `observe`, `lab`, `staging`, `prod` |
| Leash | Controls that constrain NEWTON itself (its creds, ACLs, mgmt path, profiles) |
| Effect verification | Checking the runtime state a change should produce (rendered ruleset, effective proto, leases) |
| Intent test | End-to-end assertion from a client's point of view ("guest cannot reach LAN") |
| HIL | Hardware-in-the-loop rig: DUT + serial + power control + probes |
| Certification | Per-platform test suite that must pass before writes are enabled for that platform |
