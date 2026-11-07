# 02 — Reality Check & Scope

## The question

> "Any network device has well-defined commands and docs. Train a bot on Cisco, Fortinet, Juniper,
> whatever — all their docs and manuals — then add safeguards. Once we have the docs this shouldn't be
> too hard to build, should it?"

## Short answer

The docs are the **easy 20%**, and frontier models already absorbed most public vendor docs during
pretraining. Docs get you a model that writes *plausible* config. A senior network engineer is
valuable for the other 80%: knowing what **this** box actually does, changing it **without losing
it**, **proving** the change did what was intended, and **not being manipulated** by what it reads.
That 80% is NEWTON. It is engineering, not knowledge.

---

## Seven gaps between "has read the docs" and "senior engineer"

### Gap 1 — Docs are stale, incomplete, or contradict each other
- OpenWrt's own wiki marks its `ubus uci` section as severely outdated and incomplete [V-14]. A user
  calling `uci apply` with rollback from the CLI got `Invalid argument`, and with a session got
  `no response`, with no documented resolution in that thread [V-15]. The behavior NEWTON depends on
  most (apply-with-rollback) is precisely the under-documented part → **LVR-01/02**.
- Fortinet's FortiGate CLI reference says `cfg-save revert` reverts unsaved changes after the timeout;
  the FortiProxy 2.0 CLI reference describes the same mode as *saving* them after idle [V-27].
- OpenWrt 25.12 replaced `opkg` with `apk` [V-13]. Any knowledge pack built from pre-2026 docs emits
  dead commands for package management.

### Gap 2 — Config that validates is not config that behaves
From real-hardware findings published by `openwrt-iac/uapi` [V-06]:
- A firewall rule with `proto: all` + `dest_port: 22` + `ACCEPT` renders as a bare
  **accept-everything** rule. Ports are silently dropped for protocols that can't carry them —
  a *widening*, not an error.
- Some sections are silently discarded (e.g. zone `any` is not a wildcard — only `*` is): the write
  succeeds, the rule never exists.
- nftables loads atomically: one unresolvable protocol token rejects the **entire** ruleset and the
  router **keeps the previous firewall**. Your change "applied"; nothing changed.
- netifd silently runs nothing for an interface whose protocol handler package isn't installed;
  the config reads back fine.
- uapi's maintainers state there is currently no way to ask a router which sections it will refuse
  before writing them.

**Consequence:** NEWTON must verify **effective runtime state** (rendered ruleset, effective
protocol, real DHCP leases, real reachability), not config read-back. [ADR-010]

### Gap 3 — Same intent, different mechanics per platform/version/license
- Junos `commit confirmed` reverts in place [V-03]. FortiOS `cfg-save revert` reverts **by
  rebooting** to the saved config [V-27] — a very different blast radius.
- NAPALM's IOS driver needs `archive` enabled for commit-confirm and works in whole minutes [V-26].
- Even within OpenWrt, the physical DUT (MediaTek MT7981B, DSA switch, Wi-Fi) and an x86 twin differ
  in hardware-specific config sections [V-29].

### Gap 4 — The lockout problem *is* the product
The classic senior-engineer failure is changing the interface, route, or firewall rule you're
connected through. Docs describe commands; they don't keep you reachable. Required mechanics:
device-side dead-man rollback, out-of-band console, verification from a **new** session, reboot-safe
restore, and refusing to touch the management path without extra controls. [ADR-004]

### Gap 5 — The data is hostile
Routers echo attacker-controlled strings: DHCP client hostnames, Wi-Fi scan SSIDs, LLDP/CDP names,
interface descriptions, syslog lines, banners. An agent reading "summarize connected clients" reads
whatever a stranger typed into their phone's hostname. Research on network-ops agents concludes they
need execution-time authorization boundaries, not just prompt hygiene [V-11]; architectural controls
(scoped privileges, sanitization at boundaries) cut injection success dramatically where prompt rules
alone did not [V-12]. And the same DHCP-hostname vector has a long history of command injection in
router firmware itself — never interpolate device strings into a shell.

### Gap 6 — The evidence says verification loops move the needle, not knowledge
- GPT-4 alone wrote configs with "egregious" errors; verifier-in-the-loop made them correct with far
  fewer human prompts [V-09].
- In 2026, with newer models: even state-of-the-art models fail on large scenarios and introduce new
  errors; an agent loop with a verifier and rollback cut regressions for one model from 13.3% to 0.9%
  [V-10]. That's the difference between "occasionally breaks things" and "operable."

### Gap 7 — "Every device" is a combinatorial explosion
Platform × OS version × feature × license × transport × hardware. Thousands of combinations, each with
quirks only testing reveals. You don't scale this by reading more manuals; you scale it by
**certification**: a per-platform test suite in a virtual lab that must pass before writes are
enabled, with a support **tier** that says exactly what NEWTON may do on that platform. [ADR-009, 05]

---

## What "training" should mean for NEWTON

| Approach | Verdict | Why |
|---|---|---|
| Fine-tune a model on vendor manuals | **Skip** | Goes stale at the next release, costs real money, gives no verification, and locks you to one model family (breaks your cross-model rule) |
| Bulk-scrape every vendor's docs into a vector store | **Skip as a strategy** | Retrieval of unverified, possibly outdated, copyrighted text; useful only as a citation source |
| **Agent Skills** per platform (procedures, gotchas, version notes) | **Do** | Progressive disclosure keeps context small; portable across harnesses [V-23] |
| **Verified Facts Ledger** (behavior proven in the lab) | **Do — this is the moat** | Turns docs into tested facts; versioned; machine-checkable [08] |
| Local RAG over manuals you legitimately have, with citations | **Optional** | Treat retrieved text as claims to test, and as untrusted input |
| **Doc-claim → lab-test loop** | **Do** | The agent proposes a test for a doc claim; NEWTON runs it on the twin/DUT; the ledger records the result [08] |

---

## Goals (v1)

| ID | Goal |
|---|---|
| G1 | Safe-by-construction config changes on OpenWrt 25.12: every write is a verified transaction with device-side rollback |
| G2 | Read/troubleshoot like a senior engineer: structured state, provenance, untrusted-data handling, secrets never sent to the model |
| G3 | Human authority preserved: approvals out-of-band, bound to plan hash; profiles bound to devices, not chosen by the agent |
| G4 | Effect verification + intent tests from client vantage points (probe hosts) |
| G5 | A lab that can break and heal itself: twin VM, HIL rig (serial + power), automated recovery ladder |
| G6 | A vendor abstraction proven by a **second** platform (P7) via the certification suite |
| G7 | Knowledge that improves with use: the Verified Facts Ledger |
| G8 | Harness-agnostic: works under Claude Code, OpenCode and other harnesses; cross-model benchmarkable |

## Non-goals (v1)

- Firmware upgrades/sysupgrade by the agent in 1.0 (human-only; lab automation in P5 is the exception). Planned for
  1.3 as an always-HIGH change with a firmware drill (`docs/ROADMAP.md`, "Release train").
- Multi-device atomic changes, fleet rollouts, or orchestration across sites (a canary-first fleet rollout is planned
  for 1.4, one approval per site file, stop at the first failure).
- Autonomous production changes without human approval.
- Replacing vendor controllers (Meraki, Mist, CloudVision, FortiManager).
- Fine-tuned models. Bulk doc ingestion as "training."
- A web UI. (CLI + MCP first; revisit after P8.)

## Success metrics (targets — tune in P8) [OPEN]

| Metric | Target |
|---|---|
| Chaos suite recovery (lockout, controller crash, partition, power cut) | 100% automatic recovery to LKG; time ≤ rollback timeout + 2 min |
| Executed safety violations (writes that bypassed policy) | **0** (attempted violations are logged and counted, not executed) |
| NEWTON-Bench task success (OpenWrt set) | Baseline in P8, then improve release over release |
| NEWTON-Bench regression rate (healthy intent tests broken by a change) | ≤ 1% (cf. 0.9% in [V-10]) |
| Secrets in model-bound output (fixture corpus) | **0** |
| Writes with complete evidence (pre/post snapshot, checks, journal entry) | 100% |
| Mean time to recover the DUT from a config-level brick (automated) | ≤ 10 min |

## Scope ladder for "every piece of network equipment"

1. **T0 Observe** — read-only on anything reachable via SSH/API with structured parsing.
2. **T1 Managed write** — platforms with non-disruptive device-side rollback that pass certification.
3. **T2 Managed write with caveats** — disruptive or coarse revert (reboot-based, minute granularity,
   session-scoped safe modes); approvals mandatory.
4. **T3 Never write** — no safe revert path; read-only forever unless OOB + human.

Details and the platform matrix are in `05`.
