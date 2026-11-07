# 07 — MCP & Skills Interface

## Protocol baseline

| Item | Decision | Status |
|---|---|---|
| MCP revision | Target **2026-07-28** (stateless; no `initialize`; `server/discover`; server-minted handles for cross-call state; MRTR replaces server-initiated elicitation; tasks moved to an extension; sampling/roots/logging deprecated) | [V-20] |
| SDK | **MCP Python SDK v2.x** (`mcp.server.mcpserver.MCPServer`), which serves 2026-07-28 and earlier revisions from one server; FastMCP 4 is an acceptable alternative (note: its `ctx.elicit()` is old-protocol-only) | [V-21] — pin in P0 |
| Client support | Which revision Claude Code / OpenCode negotiate today, and whether they render MRTR `input_required` to a human | [LVR-14] |
| Transport | Streamable HTTP bound to `127.0.0.1`/unix socket or Tailscale IP, client bearer token, DNS-rebinding protection, Origin validation; optional stdio→HTTP shim with no creds | [ADR-001], `03` |
| Server name | `newton_mcp`; tools are snake_case `newton_<verb>_<noun>` | mcp-builder conventions |
| Tool ordering | Deterministic `tools/list` order (spec SHOULD; helps prompt caching) | [V-20] |

Why Python despite TypeScript being the common MCP default: the network-automation ecosystem NEWTON
reuses (NAPALM, ncclient/PyEZ, pygnmi, Scrapli, TextFSM/Genie, pybatfish) is Python. [ADR-002]

---

## Tool catalog

Annotations are **hints** for clients, never security controls. Policy is enforced server-side.

### Read (readOnlyHint: true, destructiveHint: false)

| Tool | Input | Output (structuredContent) |
|---|---|---|
| `newton_list_devices` | `profile?`, `platform?`, `limit`, `cursor` | devices: id, platform, version, profile, tier, health, capabilities |
| `newton_get_device_facts` | `device_id` | facts (redacted, enveloped) |
| `newton_get_config` | `device_id`, `scope?` (e.g. `firewall`, `network.lan`), `format` (`structured`/`raw`) | snapshot (redacted), `snapshot_hash_short` |
| `newton_get_state` | `device_id`, `getter` (enum from adapter), `params?`, `limit`, `cursor` | rows with provenance; untrusted fields enveloped |
| `newton_run_diagnostic` | `device_id`, `kind` (`ping`/`traceroute`/`dns_lookup`), `target` (validated), `count≤5` | result; rate-limited; openWorldHint: true |
| `newton_query_knowledge` | `platform`, `version?`, `topic` | ledger entries (status, evidence ref) + skill reference pointers |
| `newton_get_plan` | `plan_id` | plan (diff redacted), status, approval status |
| `newton_get_transaction` | `txn_id` | states, checks, evidence summary |
| `newton_list_transactions` | `device_id?`, `since?`, `limit`, `cursor` | summaries |

### Plan & validate (no device mutation; readOnlyHint: true)

| Tool | Input | Output |
|---|---|---|
| `newton_plan_change` | `device_id`, `intent` (text, ≤ 1 KB), `ops[]` (platform op schema), `intent_tests[]` (optional; see `09`) | `plan_id`, rendered diff, touched domains, lint findings, risk, policy verdict, required approvals, verification plan, `expires_at` |
| (ADR-018) `newton_plan_change`, `newton_plan_tier` | also require `owner_confirmed_in_chat: true` and `explanation` {`intent`, `steps[]`, `expect[]`, `risk`}; refused before device contact if the flag is false or missing | plan record carries the explanation inside `plan_hash` |
| `newton_validate_plan` | `plan_id` | lint results + twin-first results (if required/available); updates plan status |

### Write (readOnlyHint: false, destructiveHint: true, idempotentHint: false)

| Tool | Input | Output |
|---|---|---|
| `newton_apply_change` | `plan_id` | terminal txn result: CONFIRMED / ROLLED_BACK / DEVICE_REVERTED / STALE / … + evidence. May return MRTR `input_required` for approval-lite cases (lab/staging, LOW–MED) |
| `newton_rollback_change` | `txn_id` | creates and executes a **revert plan** (itself policy-checked) |

### Lab (registered only when lab-profile devices exist)

| Tool | Notes |
|---|---|
| `newton_lab_reset` | `device_id`, `method` (`snapshot` for twin; `guard_restore` / `failsafe` for DUT [LVR-08]); lab profile + OOB required |
| `newton_lab_console_tail` | read-only tail of the serial console log (enveloped) |

### Deliberately **not** exposed via MCP
`approve`, `set_profile`, `break_glass`, inventory/policy edits, credential rotation, guard install,
raw shell. These live in the `newton` admin CLI on `newton-ctl` only.

`newton_raw_command` exists behind a feature flag, **lab profile only**, read-only allowlist by default,
always journaled. Off by default.

---

## Key schemas (sketch; implement as Pydantic v2 models)

```json
// newton_plan_change input
{
  "device_id": "dut1",
  "intent": "Create an isolated guest network on lan3 with internet access only.",
  "ops": [
    {"op": "add", "config": "network", "type": "device", "name": "br_guest"},
    {"op": "set", "config": "network", "section": "guest", "option": "proto", "value": "static"}
  ],
  "intent_tests": [
    {"probe": "probe-guest", "expect_dhcp_in": "10.20.0.0/24"},
    {"probe": "probe-guest", "expect_unreachable": ["192.168.1.0/24", "router:443"]},
    {"probe": "probe-guest", "expect_reachable": ["lab-isp:80"]}
  ]
}
```

```json
// newton_plan_change output (structuredContent, abbreviated)
{
  "plan_id": "pln_01JABCXYZ",
  "plan_hash": "sha256:…",
  "base_hash_short": "a1b2c3",
  "risk": "MED",
  "touched_domains": ["network.interfaces", "firewall.zones", "dhcp.pools"],
  "lint": [{"rule": "OWRT-L03", "severity": "error", "path": "firewall.@rule[4].dest", "message": "…", "fix_hint": "use '*'"}],
  "policy": {"allowed": false, "reasons": ["lint errors present"], "required_approvals": []},
  "verification_plan": {"static": ["lint", "fw4_check_on_twin"], "twin": true, "live": ["EV-01","EV-02","EV-02b","EV-02c","EV-03"], "intent_tests": 3},
  "expires_at": "2026-10-06T15:30:00Z",
  "next_steps": ["Fix lint errors and call newton_plan_change again."]
}
```

Handles (`plan_id`, `txn_id`) are server-minted and passed as ordinary tool arguments — the pattern the
2026-07-28 spec prescribes for cross-call state [V-20].

---

## Error model

Every error returns `{code, message, retryable, next_steps[]}`. `next_steps` are fixed strings written
by NEWTON (never containing device data).

| Code | Meaning | Typical next step for the agent |
|---|---|---|
| `POLICY_DENIED` | Profile/risk/leash forbids | Explain to the human; do not re-scope to evade |
| `LEASH_VIOLATION` | Touches NEWTON's own constraints or misuses a placeholder | Stop; tell the human |
| `APPROVAL_REQUIRED` | Needs out-of-band human approval | Tell the human: `newton approve <plan_id>` on newton-ctl; poll `newton_get_plan` |
| `APPROVAL_EXPIRED` | Token TTL passed | Re-request approval |
| `PLAN_STALE` | Device config changed since planning | Re-read state; re-plan |
| `PLAN_EXPIRED` | Plan TTL passed | Re-plan |
| `LINT_FAILED` | Linter errors | Fix ops per `fix_hint` |
| `TWIN_FAILED` | Twin apply or intent tests failed | Inspect evidence; re-plan |
| `DEVICE_LOCKED` | Another txn open on device | Wait; poll |
| `DEVICE_UNREACHABLE` | Can't reach mgmt plane | Report; no retries beyond 2 |
| `VERIFY_FAILED_ROLLED_BACK` | Change reverted after failed checks | Diagnose from evidence before re-planning |
| `ROLLBACK_FAILED_ESCALATED` | Device not confirmed at LKG; human paged | Stop all activity on device |
| `CAPABILITY_MISSING` | Platform lacks required capability/tier | Read-only on this device |
| `RATE_LIMITED` | Too many txns | Wait until `retry_after` |

Rule enforced in the core skill: the same plan failing twice → stop and report to the human.

---

## Output conventions

- Every tool returns `structuredContent` (JSON, schema-declared via `outputSchema`) **and** a short
  text summary for clients that only show text.
- Device-originated strings use the untrusted envelope (`04`); secrets are placeholders.
- Lists paginate (`limit` default 25, max 200; `next_cursor`, `has_more`).
- Size cap per response (default 32 KB of text); larger content → pagination or scoped getters.
- Every response includes `device_id`, `observed_at`, and the `source` (getter/ubus method) of each
  value — "unreachable," "auth failed," and "empty" are distinct results.

---

## Agent Skills packaging

Skills are folders with `SKILL.md` (YAML frontmatter `name`, `description`) plus optional
`references/`, `scripts/`, `assets/`; loaded by progressive disclosure [V-23].

| Skill | Purpose | Loads when |
|---|---|---|
| `newton-core` | Method of procedure, tool usage, hard rules, when to stop | Any network inspect/change request |
| `newton-openwrt` | uci/ubus model, 25.12 specifics (`apk`), fw4 gotchas, recovery ladder | OpenWrt devices |
| `newton-lab` | Lab ops, chaos runs, bench tasks, twin usage | Lab work |
| `newton-<platform>` (later) | Per platform after certification | That platform |

Install locations: Claude Code `.claude/skills/` (project) or `~/.claude/skills/`; OpenCode
`.opencode/skills/` or `~/.config/opencode/skills/`, and OpenCode also discovers Claude-compatible
paths [V-23]. Skills contain **no secrets, no device addresses, no credentials**. Drafts in `08`.

---

## Harness configuration

### Claude Code — MCP server
Register NEWTON as an HTTP MCP server pointing at `newton-ctl` with its client token (exact CLI/JSON
syntax: follow current Claude Code docs at implementation time).

### Claude Code — guardrail hook (defense in depth) [V-24, LVR-15]

`.claude/settings.json` (project):
```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash",
        "hooks": [ { "type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/newton_guardrail.py" } ] },
      { "matcher": "mcp__newton__newton_apply_change",
        "hooks": [ { "type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/ask.py" } ] }
    ]
  }
}
```

`.claude/hooks/newton_guardrail.py`:
```python
#!/usr/bin/env python3
"""Deny shell commands that would bypass NEWTON. Defense in depth only:
the real boundary is network isolation + no creds on the agent host."""
import json, re, sys

event = json.load(sys.stdin)
cmd = (event.get("tool_input") or {}).get("command", "")

BLOCK = [
    r"\b(ssh|scp|sftp|sshpass|telnet|nc|ncat|socat)\b",
    r"\b(ubus|uci|fw4|nft)\b",
    r"/ubus\b",
    r"\bnewton\s+(approve|profile|break-?glass)\b",
    r"\b10\.99\.0\.\d+\b",   # lab mgmt subnet (example) - keep in sync with inventory
]
for pat in BLOCK:
    if re.search(pat, cmd):
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Use newton_* MCP tools for device access; direct device/approval commands are blocked."}}))
        sys.exit(0)
sys.exit(0)  # no decision -> normal permission flow
```

`ask.py` returns `permissionDecision: "ask"` so a human sees every apply in interactive sessions.
Test that both hooks actually fire and block on your Claude Code version (RT-07, [LVR-15]).

### OpenCode / Hermes
Configure equivalent permission controls [OPEN]. Regardless of harness, the network-isolation boundary
(agent host cannot reach device mgmt planes or `newton-ctl`'s shell) is what makes bypass impossible.
