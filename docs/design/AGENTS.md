# AGENTS.md — NEWTON

NEWTON is an MCP server + Agent Skills that let an AI agent read, plan, change, verify, and roll back
network device configuration safely. First platform: OpenWrt 25.12. Design docs: `docs/design/`.

> Claude Code users: import this file from your project's own `CLAUDE.md` with an `@` import (verify that
> your Claude Code version supports it before relying on it).

## Current phase
Open `docs/ROADMAP.md`: it names the released and planned releases. Do not start work belonging to a later release.

## Read before coding
1. `docs/ROADMAP.md` (the current release only)
2. `docs/design/03-ARCHITECTURE.md`
3. `docs/design/04-SECURITY-AND-SAFETY-MODEL.md`
4. The spec for your area: `05` (adapters), `06` (OpenWrt), `07` (MCP/skills), `08` (knowledge), `09` (tests)
5. `docs/design/11-ADRS.md`; status tags are defined in `docs/design/00-README.md`

## Hard rules
1. **Tests first.** Write the failing test, reference its ID, then implement. Every behavioral change
   has a test. No exceptions for "small" changes in `policy/`, `txn/`, `redact/`, `untrusted/`,
   `adapters/`, or the on-device guard.
2. **No secrets or real device data in git.** No credentials, real IPs/hostnames from the maintainer's networks,
   Wi-Fi keys, or captured configs. CI uses synthetic fixtures only.
3. **No shell string building. Ever.** Use argv lists; never `shell=True`, `os.system`, `eval`, or
   `sh -c` with interpolated values. Device strings and model output are untrusted.
4. **Never weaken safety to make a test pass.** Policy, leash rules, profiles, and approval checks
   change only with an ADR or the maintainer's explicit approval in the PR.
5. **Forbidden MCP tools:** anything that approves, changes profiles, edits inventory/policy, rotates
   credentials, installs the guard, or exposes a raw shell. `newton_list_tiers` and `newton_plan_tier`
   are allowed because a tier is a hardening level, not a device profile, and `newton_plan_tier`
   only plans (apply stays on the existing plan/approve/apply flow). (The only exception is the lab-only,
   feature-flagged `newton_raw_command`, read-only allowlist by default.)
6. **Every write path arms device-side rollback first** and has a test proving the device reverts when
   confirm is withheld.
7. **Verification uses a new session.** Never confirm based on the session that applied the change.
8. **Never auto-confirm after a restart.** Reconciliation rolls back or records DEVICE_REVERTED.
9. **Untrusted data:** every device-originated string goes through the untrusted envelope; never into
   tool names, tool descriptions, error `next_steps`, or log format strings.
10. **Secrets:** every model-bound output goes through redaction; placeholders only mean "keep at the
    same path."
11. **LVR discipline:** code that depends on an `[LVR-nn]` item ships with the test that verifies it.
    When that test passes on the DUT, update `docs/design/12-VERIFICATION-LEDGER.md` in the same PR.
12. **Pinned dependencies.** Don't bump the MCP SDK major version or add network-facing dependencies
    without an ADR.
13. **Lab access:** `unit`/`contract` tests never touch the network. `twin`/`hil`/`chaos`/`bench`
    require `NEWTON_LAB=1` and the lab lock.
14. **Protected paths:** in unattended runs, do not modify `docs/design/`, `skills/`, `policy/`, or this
    file. Propose changes in the PR description instead.
15. **Never contact devices directly** (ssh, curl to `/ubus`, etc.) from your tooling. Use the test
    harness or NEWTON itself.

## Commands
See `docs/TESTING-METHOD.md`: it holds the real runner and the suites, as checked in the repo.

## Code style
Python 3.12, full type hints, Pydantic v2 models for every tool input/output and plan/txn object,
async I/O, structured logging to stderr (never stdout in stdio mode), pyright strict for `policy/`,
`txn/`, `redact/`, `untrusted/`. Small modules; no clever metaprogramming in safety code.

## Pull request checklist
- [ ] Test IDs added/changed (from `docs/design/09-LAB-AND-TEST-STRATEGY.md` or new ones)
- [ ] Risk level (LOW/MED/HIGH) and files/lines touched
- [ ] LVRs touched or closed; ledger/`12` updated if closed
- [ ] No secrets/real device data (secret scan green)
- [ ] For safety-kernel and transaction changes: validator (different model family) reviewed against `04`

## Definition of done
Failing test first → implementation → `unit` + `contract` green → relevant lab suites green if safety
code changed → docs/ledger updated → PR checklist complete.
