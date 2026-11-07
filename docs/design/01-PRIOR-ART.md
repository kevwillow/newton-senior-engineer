# 01 — Prior Art & Positioning

Research date: 2026-10-06. Star/fork counts and skill counts drift daily; treat them as snapshots.

## Verdict

**Pieces of NEWTON exist. The whole does not — at least not that this research found.**

- An open-source "CCIE-level AI network engineer" already exists and is large: **NetClaw** [V-01].
- Vendor and community MCP servers already do **commit-confirmed** changes on Junos [V-02, V-03, V-04].
- At least half a dozen **OpenWrt MCP servers** exist, but the ones reviewed are thin wrappers that
  run commands as root over SSH, with no transactional rollback described [V-05].
- Commercial vendors sell **agentic ops + digital-twin verification** for enterprise estates
  (Cisco AgenticOps, Forward AI / Forward Predict) [V-07, V-08].
- Academic work in 2023–2026 keeps landing on the same conclusion: **verification loops, not more
  knowledge, are what make LLM-driven config safe** [V-09, V-10], and network agents need
  **execution-time authorization boundaries** against prompt injection [V-11, V-12].

**Gap NEWTON can own:** a *safety-kernel-first*, vendor-neutral transaction layer (plan → arm
device-side rollback → apply → verify effect from a fresh session → confirm/rollback), with
**OpenWrt as a first-class target** and a **lab-verified knowledge ledger**. That combination did not
show up in this search.

---

## Landscape

### Open-source agents and MCP servers

| Project | What it is | Safety model (as documented) | Lesson for NEWTON |
|---|---|---|---|
| **NetClaw** (`automateyournetwork/netclaw`) [V-01] | Apache-2.0 agent on the OpenClaw framework, powered by Claude; ~670 stars / ~186 forks at research time. Its `SOUL.md` lists 233 skills backed by 173 MCP servers: pyATS, Junos, Batfish, SuzieQ, ANTA, Fortinet, CML, containerlab, GNS3, EVE-NG, NetBox/Nautobot, ITSM, observability… | Rules in the persona file (never guess state, baseline before change, no destructive commands); prod changes gated on an approved ServiceNow CR; GAIT audit trail; multivendor server **read-only by default with write tools absent unless enabled**; **writes single-pathed per platform**; optional DefenseClaw guardrails / OpenShell sandbox. | Borrow: platform-first routing, single write path per platform, provenance on every value, explicit "empty result ≠ absence" semantics. Be aware: a lot of the rule set is prompt-level (one section openly says its guardrails are "guidance, not code"), and the persona instructs the agent to update its own files without asking — a persistence surface for injected instructions. OpenWrt is not in its listed platform families. |
| **Juniper `junos-mcp-server`** (official) [V-02] | MCP server for Junos; stdio + streamable-HTTP | Has a "guardrails for config commit" section; README warns to use it only if company policy allows sending Junos data to LLM services and to deploy locally until secured | Data-egress policy is a first-class concern, not an afterthought |
| **`shigechika/junos-mcp`** [V-03] | MCP front-end for `junos-ops` | `push_config`: lock → load → diff → commit check → **commit confirmed** → health check → confirm → unlock; auto-rollback on failed health check | This is the canonical transaction shape. NEWTON generalizes it to platforms that lack native commit-confirm |
| **`anderson-jason573/juniper-junos-mcp`** [V-04] | Community Junos MCP (NETCONF/PyEZ) | Preview is **re-validated against the device before commit** (detects config drift); commit confirmed; **reconnects on a new session** to prove reachability before confirming; "the model picks a tool, never a command" | Optimistic concurrency (base-config hash) + fresh-session verification. Its README also warns the MCP endpoint has **no auth** — don't repeat that |
| **OpenWrt MCP servers** (`s09x/openwrt_ssh_mcp`, `jsebgiraldo/openwrt_ssh_mcp`, `Necho-dev/openwrt-cli`, read-only iStoreOS/ubus variants) [V-05] | SSH or ubus wrappers exposing system/network/package tools | READMEs reviewed say root SSH access; `openwrt-cli` adds an `mcp.mode` guard and keeps passwords out of client config; read-only variants exist | The demand is real; the safety layer is missing. NEWTON should not be "one more wrapper" |
| **`openwrt-iac/uapi`** [V-06] | Native REST API for OpenWrt built as a Terraform-provider backend | Validates payloads against what firewall4 actually applies | Its v2.4.0 release notes are the best public catalog of **OpenWrt silent-failure modes** (see `02`, `06`). Mine the *behaviors* for NEWTON's linter and tests (re-implement; check license before reusing code) |

### Commercial

| Product | Relevance |
|---|---|
| **Cisco AgenticOps / AI Canvas / Deep Network Model** [V-07] | Expanded across the Cisco portfolio in Feb 2026, including risk-aware validation of changes against live topology/config/telemetry with blast-radius analysis. Vendor-locked to Cisco-managed estates. |
| **Forward Networks — Forward AI + Forward Predict** [V-08] | Agentic layer on a mathematical network digital twin (announced Jan 29, 2026); Predict models a proposed change's impact before it touches production; exposed to agents via REST/MCP. Enterprise, multi-vendor, not OpenWrt/SMB. |

### Research (what the evidence says)

| Work | Finding relevant to NEWTON |
|---|---|
| Mondal et al., *What do LLMs need to synthesize correct router configurations?* (HotNets 2023) [V-09] | GPT-4 alone produced plausible drafts with egregious topology/syntax/semantic errors; pairing it with verifiers (Batfish + semantic checkers) and localized feedback gave ~10× (Cisco→Juniper translation) and ~6× (no-transit policy) leverage. |
| Asadli et al., *Evaluating Agentic Configuration Repair* (ETH Zürich, AIWILD @ ICML 2026) [V-10] | Even state-of-the-art models fail on large misconfiguration scenarios and often introduce new errors. Agentic scaffolding (retrieval + iterative edits + Batfish feedback + rollback) improved repair efficacy ~12% and safety ~17% on average; for GPT-5 mini, regressions fell from 13.3% (single-shot) to 0.9% (agentic + verifier, 20 steps). Benchmarks named: CORNETTO, NetArena, NIKA. Notes production deployments at hyperscalers (NetAssistant, BiAn, Confucius). |
| *NetInjectBench* (arXiv 2607.10490, Jul 2026) [V-11] | Indirect prompt injection via tickets, alerts, logs, runbooks, ChatOps; attack patterns include fake approval, fake emergency, fake vendor authority, poisoned runbook. Conclusion: network-ops agents need **execution-time authorization boundaries** alongside prompt hygiene. |
| Multi-agent injection threat model (arXiv 2609.22949) [V-12] | Indirect injection via tool outputs succeeded in 43% of attempts in their test system; four architectural defenses cut overall success from 31.2% to 4.2%; **privilege-scoped tool access eliminated privilege escalation entirely.** |

### Building blocks to reuse (not rebuild)

| Block | Use in NEWTON |
|---|---|
| **NAPALM** [V-26] | Multi-vendor driver API with `commit_config(revert_in=…)`, `has_pending_commit()`, `confirm_commit()`, `rollback()`. NEWTON's adapter contract mirrors it; wrap NAPALM for supported platforms. |
| **containerlab** [V-25] | Virtual multi-vendor lab; kinds include OpenWrt, Arista cEOS, Juniper vJunos-router, Cisco IOL/XRd, Nokia SR Linux, FortiGate, MikroTik, VyOS, FRR, SONiC. |
| **Batfish** [V-28] | Static verification for Arista, Cisco, Juniper, Fortinet, Palo Alto, Check Point, Cumulus, F5, SONiC, A10, AWS, Azure. **Not OpenWrt** → NEWTON uses a twin + linter there. |
| **MCP Python SDK v2 / FastMCP 4** [V-21] | Serve MCP 2026-07-28 and older revisions from one server. |
| **Agent Skills standard** [V-23] | Portable knowledge packs across Claude Code, OpenCode, Codex, Cursor, etc. |

---

## Positioning

NetClaw is breadth-first and enterprise/Cisco-centric. Vendors are platform-locked. Forward is
enterprise and model-based. **NEWTON should be depth-first on safety**:

1. **Safety kernel as the product** — transactions with device-side dead-man rollback, effect
   verification, out-of-band approvals bound to plan hashes, leash rules. Enforced in code.
2. **OpenWrt / prosumer / SMB first** — where there is no vendor AI and the hardware is cheap enough
   to build a real HIL lab (you already have identical spare hardware).
3. **Lab-verified knowledge** — a ledger of behaviors proven on real targets, which is the thing
   "trained on docs" can never give you.

## Build vs. adopt — recommendation [ADR-011]

- **Build**: policy engine, transaction engine, OpenWrt adapter + on-device guard, verification
  engine (linter, effect checks, intent tests), knowledge ledger, NEWTON-Bench.
- **Reuse**: NAPALM / ncclient / pygnmi drivers, containerlab, Batfish, MCP SDK, Agent Skills format.
- **Interoperate, don't fork**: run vendor/community MCP servers (Junos, NetBox, etc.) alongside
  NEWTON for read-only enrichment if useful — but writes go only through NEWTON's transaction path
  ("single write path per platform," the same rule NetClaw uses).
- **Revisit at P7**: if NEWTON's transaction layer is solid, contributing the OpenWrt adapter or the
  transaction pattern to the broader ecosystem (including NetClaw) is a legitimate option.

## Patterns to borrow

- Lock → load → diff → check → commit-confirmed → health check (fresh session) → confirm → unlock [V-03, V-04]
- Re-validate the plan against the live device right before apply (drift = abort) [V-04]
- Tools, not commands: the model chooses a typed tool; the server renders the device syntax [V-04]
- Write tools absent from the tool list unless explicitly enabled; single write path per platform [V-01]
- Every reported value carries its source; "unreachable", "auth failed", and "empty" are different facts [V-01]
- Era-portable approvals: MRTR elicitation for new MCP clients, legacy elicitation for old ones,
  approval-token fallback (pattern seen in `mcp-odoo` v1.3.0) [V-22]

## Patterns to avoid

- Root SSH key handed to the agent's shell (every OpenWrt wrapper reviewed) [V-05]
- Safety rules that exist only as prompt text the model can ignore or be talked out of [V-11, V-12]
- An agent that rewrites its own instruction/persona files without review (persistent injection)
- Unauthenticated MCP endpoints [V-04]
- Treating config read-back as proof of effect [V-06]
