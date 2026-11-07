# 11 — Architecture Decision Records

Format: Status · Context · Decision · Options considered · Consequences · Follow-ups.
Deciders: the maintainer. Date for all initial records: 2026-10-06.
Changing a decision = add a new ADR that supersedes the old one; never edit history silently.

---

## ADR-001 — Product shape: MCP server (capabilities) + Agent Skills (knowledge)
**Status:** Accepted
**Context:** NEWTON must work under Claude Code, OpenCode and Hermes, and keep the
cross-model independence rule. Safety must be enforceable, not advisory.
**Decision:** Ship two artifacts: `newton_mcp` (all device interaction, all enforcement) and a set of
Agent Skills (procedures, platform knowledge). Both are open standards [V-20, V-23].
**Options considered:**
| Option | Verdict |
|---|---|
| Skill-only (instructions + shell access) | Rejected — safety rules in text are bypassable [V-11, V-12] |
| Monolithic agent on one framework (NetClaw/OpenClaw style) | Rejected — harness lock-in; conflicts with cross-model goal |
| Custom REST API + CLI only | Rejected — loses harness portability; MCP is the integration standard |
**Consequences:** Two artifacts to version together. Exposure to MCP spec churn (2026-07-28 was
breaking [V-20]) is mitigated by SDK v2 serving multiple revisions [V-21].
**Follow-ups:** SPK-3 confirms what current clients negotiate [LVR-14].

## ADR-002 — Language & stack: Python 3.12 + MCP Python SDK v2
**Status:** Accepted
**Context:** Many MCP guides default to TypeScript. NEWTON's value depends on network libraries.
**Decision:** Python 3.12; MCP Python SDK 2.x (FastMCP 4 acceptable); Pydantic v2; httpx/asyncssh;
pyright strict on safety modules.
**Options considered:** TypeScript (strong MCP SDK; weak network ecosystem) — rejected. Go (single
binary; minimal network-automation libs) — rejected for core; acceptable later for the on-device guard
if ucode/sh proves insufficient.
**Consequences:** Reuse NAPALM, ncclient/PyEZ, pygnmi, TextFSM/Genie, pybatfish directly. Must pin
SDK and treat major upgrades as ADR-worthy.

## ADR-003 — The LLM proposes; deterministic code disposes
**Status:** Accepted
**Context:** Models err and can be manipulated; network-ops agents need execution-time authorization
boundaries [V-11]; privilege-scoped tools eliminated privilege escalation in tests where prompt rules
did not [V-12].
**Decision:** Policy evaluation, risk scoring, approvals, transaction control, and verification
verdicts are deterministic code. No LLM call participates in a safety decision. Raw device commands
are off by default (lab-only flag).
**Options considered:** LLM-as-judge gate before apply — rejected *as a control*; allowed as an
advisory signal (e.g. a different-family reviewer) whose output can't approve anything.
**Consequences:** More upfront engineering; behavior is testable and auditable.

## ADR-004 — Device-side dead-man rollback is mandatory for any write
**Status:** Accepted
**Context:** A rollback timer in the agent or controller dies with them; lockouts cut the very path
used to fix them.
**Decision:** No write without `DEVICE_SIDE_ROLLBACK` (native commit-confirm or NEWTON guard).
Verification from a new session before confirm. Never auto-confirm after a controller restart.
**Options considered:** Controller-side timers; manual rollback; "careful prompting" — all rejected.
**Consequences:** Platforms lacking a revert mechanism are T0/T3 (`05`). OpenWrt needs a guard (ADR-006).

## ADR-005 — OpenWrt access path
**Status:** Superseded by ADR-016
**Context:** Every OpenWrt MCP server reviewed uses root SSH [V-05].
**Decision:** Primary: rpcd JSON-RPC with a dedicated ACL-scoped user [V-17]. Secondary: SSH key with
forced command + `restrict` to a strict-grammar shim [V-18]. OOB: serial console.
**Options considered:**
| Option | Verdict |
|---|---|
| Root SSH key | Rejected — no scoping; shell access invites string-built commands |
| uapi-style REST daemon on the router [V-06] | Deferred — adds an on-device service; revisit if rpcd ACLs prove too coarse |
| LuCI scraping | Rejected |
**Consequences:** Coarse device-side scoping (per config file) + semantic scoping in policy.

## ADR-006 — OpenWrt rollback mechanism
**Status:** **Proposed — decide after SPK-1**
**Context:** rpcd has native `uci apply {rollback,timeout}` + `confirm` [V-14, V-16], but CLI usage is
poorly documented [V-15] and reboot behavior is unknown [LVR-02].
**Options:**
| Option | Pros | Cons |
|---|---|---|
| A — rpcd native | No device footprint; same path as LuCI | Session semantics unclear; likely not reboot-safe |
| B — NEWTON guard (LKG on flash, uptime timer, boot-time restore) | Reboot-safe; reusable on Linux+FRR; fully testable | On-device code to maintain; LuCI edits during the window get reverted |
| A + B | Defense in depth | Two mechanisms to reason about |
**Leaning:** B as the authority, A optionally layered.
**Decision criteria:** CS-06/07/08/09 results on twin + DUT; guard test coverage; flash-space impact.

## ADR-007 — Secrets: path-bound placeholders, never sent to the model
**Status:** Accepted
**Decision:** Redact by known paths, then patterns, fail-closed on secret-like option names;
placeholders carry a keyed fingerprint; a placeholder in an op means "keep existing at this exact
path" only; new secrets come from NEWTON generation or the human channel; journals store fingerprints.
**Options considered:** No redaction — rejected. Refuse to read secret-bearing configs at all —
rejected (too limiting). Local-model-only — complementary, not a substitute.
**Consequences:** Per-platform secret catalogs + tests (RD-xx); RT-10 guards placeholder misuse.

## ADR-008 — Profiles and approvals
**Status:** Accepted, **Amended by ADR-016** (approvals are HMAC tokens the router checks; ADRs-008's
Ed25519 wording no longer matches 1.0).
**Decision:** Profiles (`observe`/`lab`/`staging`/`prod`) are bound to devices in inventory and
changeable only via the admin CLI. Approvals are Ed25519 signatures over the canonical plan identity
(incl. `plan_hash`, `base_hash`), single-use, expiring, issued on `newton-ctl`. MRTR/elicitation
counts as approval only for lab/staging LOW–MED and lab CRITICAL "approval-lite."
**Options considered:** Approval via chat message — rejected (forgeable, injectable [V-11]). MCP
elicitation for all approvals — rejected (autonomous clients answer elicitations themselves; pattern
of era-portable confirmation with token fallback seen in [V-22]).
**Consequences:** Solo-operator "cool-off" substitutes for two-person rule on prod CRITICAL.

## ADR-009 — Multi-vendor strategy: certification tiers, reused drivers, no fine-tuning
**Status:** Accepted
**Context:** Verification loops, not knowledge, drive correctness [V-09, V-10]; platform mechanics
differ materially [V-26, V-27].
**Decision:** Tiers T0–T3; per-platform certification suite CS-01…12; reuse NAPALM/ncclient/pygnmi;
skills + ledger for knowledge; no fine-tuning; no bulk doc ingestion as "training."
**Consequences:** Slower platform growth, but each added platform is trustworthy.

## ADR-010 — Verification: effect checks, intent tests, twin-first, static where available
**Status:** Accepted
**Context:** Read-back is not effect: silent discards, widenings, atomic rejections [V-06].
**Decision:** Every txn runs new-session mgmt check + platform effect checks + intent tests from
probes. Twin-first for HIGH+ when no static verifier exists; Batfish for supported vendors [V-28];
OpenWrt semantic linter before any of it.
**Consequences:** Probe infrastructure and twins are first-class lab assets.

## ADR-011 — Build vs. adopt
**Status:** Accepted, **pending OQ-01** (personal tool vs. open source vs. client use)
**Decision:** Build the safety kernel, transaction engine, OpenWrt adapter + guard, verification,
ledger, and bench. Reuse drivers and lab tooling. Interoperate with existing MCP servers for read-only
enrichment; don't fork NetClaw [V-01]. Revisit at P7 (contribute upstream or integrate).
**Consequences:** OQ-01 affects licensing, what the knowledge layer may contain (vendor-doc
copyright), and data-egress strictness.

## ADR-012 — Audit and evidence
**Status:** Accepted
**Decision:** Hash-chained JSONL journal with periodic anchors to a separate sink; per-device git of
redacted config snapshots, one commit per CONFIRMED txn; evidence bundle per txn (pre/post snapshot
hashes, check results, console excerpt hash).
**Consequences:** `newton doctor` verifies the chain; tests AU-01…03 and RD-xx enforce integrity and
secret-free storage.

---

## ADR-013 — OpenWrt rollback mechanism decided: the NEWTON guard (supersedes ADR-006's proposal)
**Status:** Accepted, 2026-10-06 (the maintainer's go for 1.0 item 4).
**Context:** Measured on lab-r1 (OpenWrt 25.12.5) on 2026-10-06: rpcd keeps its rollback copy in RAM
(`/var/run/rpcd/snapshot-files`, changed packages only). A reboot, a power cut, an rpcd reload or an rpcd restart
inside the window loses the rollback and the change stays; with nothing confirming, or the controller killed, rpcd
reverts byte-identical. LVR-02 is confirmed.
**Decision:** Option B: the on-router guard (last-known-good copy on flash, a procd-managed uptime timer, a boot-time
restore before network) is the rollback authority for 1.0. How it layers with rpcd's own timer is settled when the
guard is wired into the change protocol. **Open point closed by ADR-016:** the guard window is T+30, armed just before
rpcd's apply; rpcd confirms first, the guard second; `abort` settles both; `status` reads guard state and config
hashes; the guard's `valid_timeout` upper bound moves from 600 to 900 s (design 6.1, 6.3).
**Consequences:** On-router code to maintain and test (crash safety, idempotent restore, boot-loop escape). LuCI edits
made during an armed window are undone by a restore.
**Follow-ups:** the guard (standalone); then its wiring into the protocol once the access method is chosen
(ADR-014).

## ADR-014 — Router access method for 1.0: deferred, build transport-neutral
**Status:** Superseded by ADR-016
**Context:** Both candidates from ADR-005 work on lab-r1 (2026-10-06): (a) a Newton-only SSH key pinned with
`command=` / `restrict` to one on-router program (dropbear 2025.89 honours both); (b) an rpcd login with a limited ACL
user over uhttpd `/ubus` (allowlisted writes work; writes outside the ACL return permission denied). Pulsar ships the
same packages. Two outside reviewers both named root SSH with free-text uci batches as the largest remaining hole.
**Decision:** Choose later, before the safety kernel's router side; build the guard and the controller side of the
kernel so either transport can drive them. Recommendation: (b).
**Consequences:** Root SSH stays the transport until the choice; items 3 and 4 avoid transport-specific code.

## ADR-015 — Safety kernel for 1.0: entry point, credentials, approvals, profiles
**Status:** Accepted, 2026-10-06.
**Context:** The agent runs as the maintainer's own user, so it can read Newton's router credentials, use the maintainer's SSH key, call
the scripts directly and set its own approval flag: every rule is advice, not enforcement (design F2, ADR-001).
**Decision:**
- A `newton` system user owns the router credentials and runs the MCP server; MCP clients start
  `sudo -u newton newton-mcp` (one sudoers line for exactly that command, no arguments); stdio stays.
- The maintainer's personal SSH key is removed from root on the routers Newton manages (Pulsar once Newton has its own credential
  there; Quasar only when Newton manages it); the maintainer keeps the root password, LuCI and the console.
- Approval is `newton approve <plan>` in the maintainer's terminal with a passphrase the agent never sees; single-use; bound to
  the plan hash, the router's config hash and the device; expires after 30 minutes. A TTY check alone is not enough.
- Profiles: lab-r1 and Pulsar are `lab` (auto-apply); Quasar and any other real router are `prod` (every write needs an
  approval); leash operations (dropbear, rpcd, uhttpd, users, keys, the management interface or zone, WAN exposure) need
  an approval on every profile.
**Options considered:** a local HTTP service with a token (rejected for 1.0: every harness would need the HTTP
transport); keeping the maintainer's key behind `ssh-add -c` or as is (rejected); y/N or phone-push approvals (rejected for 1.0;
phone push may come later); approval for every write in the lab (rejected: lab testing must stay automatic).
**Consequences:** The agent keeps root on apollo for the lab, so it can always reach the lab VMs' consoles: the F2
isolation test is meaningful on Pulsar and real routers, not on lab VMs.
**Follow-ups:** The item 3 build plan (K1-K9).

## ADR-016 — Router access method for 1.0: a restricted SSH key to one on-router program
**Status:** Accepted, 2026-10-07 (design section 12).
Built on the host side; the live checks in design 9.4 are not recorded as run on the lab devices.
**Context:** ADR-005 picked rpcd primary; ADR-014 deferred the choice. The 2026-10-07 decision made the SSH forced
command primary for 1.0. ADR-013 left the guard/rpcd layering open and ADR-008 described approvals as Ed25519
signatures; both need to fit the new design.
**Decision:** Supersedes ADR-005 and ADR-014; amends ADR-008.

**(a) Access path.** A new restricted SSH key per agent is added to `/etc/dropbear/authorized_keys` on the
router. The key line pins the on-router program as its forced command:
`restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty,command="/usr/libexec/newton/newton-router --caller=<label> --role=<change|read>"`.
`<label>` matches `^[a-z][a-z0-9-]{1,31}$`; `<role>` is `change` or `read`. Setup writes the line; a client
cannot. The forced command is the only thing Newton's key can run. The program holds a closed grammar of 24
subcommands (design 3.4); every argv class is anchored (3.3); the request alphabet is fixed; stdin is bounded
and never read by a no-stdin subcommand; no request, stdin or router value becomes shell code, a `printf`
format, an `awk` program or a command word (design 3.1). The pushed helper and `sh -n` from 1.0 are gone: the
helper is installed on the router at `/usr/libexec/newton/newton-safe-apply` by the setup tool; the agent
host talks to the program only (design 1.2, 2.1, 2.4). The root password SSH lane stays for the maintainer and the lab
(direct mode). rpcd-over-uhttpd is a second door in a later release (design section 11); until
that release ships, the program refuses `--rpcd` with `door-not-built`.

**(b) Guard layering (closes ADR-013's open point).** The guard window is T+30, armed by the program with
`newton-guard arm <SID> <T+30>` just before the program calls `ubus call uci apply` (rpcd's apply). rpcd
confirms first, the guard second. `abort` settles both. `status` reads guard state and config hashes (post
hash vs base hash). The guard's `valid_timeout` upper bound moves from 600 to 900 s (RD10; design 6.1).

**(c) Probe set.** The free-form shell `check` is gone. It is replaced by 19 fixed probe types, lines
TAB-separated and LF-terminated, sealed on the router at plan time (design 4.1, 4.3):
`fail`, `ping`, `resolve`, `service-running`, `uci-equals`, `uci-unset`, `listen`, `nft-rule`,
`nft-rule-order`, `nft-rule-near`, `nft-set-has`, `conf-has`, `proc-args`, `iface-field`, `iface-absent`,
`sysctl-equals`, `ra-absent`, `log-has`, `root-password-class`. The MCP refuses `uci-equals` and `uci-unset`
probes on options that `redact._looks_like_secret_option` flags (design 7.2). An empty probe list means only
the built-in steps (ping, DNS, DHCP test, health) run, as `check = "true"` did.

**(d) Approval mode (amends ADR-008).** The router classifies every staged change itself (design 5.2). When
approval is required, the router checks an HMAC token: token =
HMAC-SHA256(K, `newton-approval-v1\n<digest>\n`), 64 lowercase hex, where K = PBKDF2-HMAC-SHA256(the maintainer's
approval passphrase in UTF-8, salt = UTF-8 `newton-approve-v1:` + device-id, 600000 iterations, 32 bytes)
and digest = sha256 hex of `newton-plan-v1\n<device-id>\n<SID>\n<base>\n<diff>\n<probes-sha>\n<T>\n`
(computed by the router at `seal` and again at `apply`). The token is single-use, bound to the router's own
digest of device, session, base, diff, probes and T, and never reaches the controller's log. The host keeps
the 30 minute expiry from the approval; the router bounds stage age by uptime and boot id and never reads
the wall clock (design 5.4, 6.2 step 3). What this protects: a hostile agent (T-A) never sees the
passphrase, K or the token; a stolen newton key (T-B) cannot apply a leash or `prod` change; the rules bind
every Newton credential that does not hold root on the router. What it does not protect: root on the router
(the maintainer's password, LuCI, console) bypasses Newton; a stolen router's flash supports an offline PBKDF2 guess
of that router's passphrase (600000 iterations slow it); on `lab` the code-exec codes are best effort (5.2);
`read` returns raw config to the controller and redaction runs on it before the model sees it;
`backup` hands `/etc/config` only (RD5 = A; design 5.5).

---

## ADR-017 — Dual-WAN failover: netifd metrics plus a health script, not mwan3
**Status:** Accepted, 2026-10-16 (the maintainer).
**Context:** ROADMAP item 8 and the design said mwan3; mwan3 2.12 is iptables-based and not recommended on 25.12;
the need is failover only.
**Decision:** netifd interface metrics order the default routes (wan=10, wan2=20, already set); a router-resident
health script (`scripts/newton-wan-health.sh`, installed by `scripts/newton-router-setup`, started by a procd
init script, enabled by UCI package `newton_wanhealth` through a normal Newton change) probes each WAN with
`ping -I <device>`, and on a dead WAN changes the default route at runtime only — it never writes UCI or files
under `/etc`, so config hashes do not move on a flap.

**Failover time budget.** Detection of a dead WAN takes at most
`down_after * (interval + K * timeout) + interval` seconds, where K is
the number of probe targets. Let I=`interval`, T=`timeout`, and D=`down_after`.
Each failed round together with the sleep before it costs up to I+K*T
because `probe_iface` pings each of K targets in turn with `-W timeout`
and stops at the first answer. Detection therefore takes at most D*(I+K*T);
the trailing `+ interval` is margin for per-round overhead. This bound assumes
the other WANs probed in the same `do_round` answer promptly; if a second WAN
is also dead, that round's WAN adds up to K*timeout to the per-round cost. Restoration
of a healthy WAN takes at most
`up_after * (interval + K * timeout) + interval` seconds by the same
arithmetic on `up_after`. With the script's defaults (interval=5,
timeout=2, down_after=3, K=1) the failover budget is 26 s; with K=2 it
is 32 s. The dual-WAN lab scenarios `dw-01-failover`, `dw-02-failback`,
`dw-05-failover-ifdown` in `lab/scenarios/dualwan/` apply a tighter
batch (interval=3, timeout=1, down_after=3, up_after=2) with K=1 and
so enforce a 15 s failover budget and an 11 s failback budget. The
WH_INTERVAL / WH_TIMEOUT / WH_DOWN_AFTER / WH_UP_AFTER / WH_TARGETS
values at the top of each effect cmd are copied by hand from the
same scenario's `batch`; the lab test
`test_dualwan_scenario_effect_sets_wh_vars_from_batch` fails if they
differ. The budget itself is computed from those WH_* values via
`lab/dualwan-lib.sh:wh_budget`.
**Consequences:** no load balancing; carrier loss and real hardware are not yet tested (Pulsar, item 9); mwan3
can be revisited if balancing is wanted.

## ADR-018 — Explain before every change; approve every change out of band
**Status:** Accepted, 2026-10-18 (the maintainer: "every change i want the agent to explain what it will do and why, and ask
for double confirmation before doing anything"; lab carve-out confirmed the same day).
**Context:** approval covered what Newton can see (diff, touched sections, leash) but not why the agent proposed the
change. For unverified vendors and for OpenWrt, the owner wants the agent's reasoning shown, and two confirmations
before anything runs.
**Decision:**
1. `newton_plan_change` and `newton_plan_tier` require `owner_confirmed_in_chat: true` (a declaration by the agent,
   backed by the SKILL.md Step 0 rule; Newton cannot see the chat) and an `explanation`: `intent` (one line),
   `steps` (one reason per change line), `expect` (1-8 structured claims), `risk` (one or two lines). A false or
   missing flag is refused before any device contact.
2. A change line is a non-blank line of the resolved batch that does not start with `#`, plus each
   `# dropped placeholder:` line Newton writes when it drops a placeholder. Plan, apply and `newton-approve` count
   the same stored batch. An agent-supplied line may not start with that marker.
3. An `expect` claim is structured, never executable: `uci_equals` (path, value) or an existing probe other than
   `fail`, validated by the probe table. Secret-looking options and values are refused. The post-apply check runs them.
4. Agent text is printable only: control, format, separator and blank-looking characters are refused, not
   stripped. Secrets in fields are masked by the redactor; a secret written as prose is not detected.
5. `explanation` and `owner_confirmed_in_chat` are plan-hash fields; editing either invalidates the approval. A
   record without them is refused at approve and apply.
6. Every plan requires out-of-band approval through `newton-approve`. The one exception (the lab carve-out,
   `approval_gate.LAB_APPROVAL_CARVEOUT`) is a device with both `profile = "lab"` and boolean `lab = true`, which
   keeps the earlier rule so automated lab scenarios run. Production devices never take it. Apply refuses a
   no-approval record for any other device.
7. `newton-approve` shows Newton's own facts first, then "Agent's explanation (unchecked claims)" with every agent
   row prefixed `| `, then an advisory mechanical check (steps naming sections Newton does not touch; touched
   sections no step names; INCOMPLETE when diff lines could not be checked).
**Consequences:** the explanation is a claim, not proof; the post-apply check tests the claims on the device: each claim is sealed as a probe after Newton's own and the caller's probes, in the one list the router verifies from a fresh session, so the claims sit inside the plan hash through `probes` and `explanation`. A claim only adds a line (none is merged with or replaces another; a duplicate keeps its own line so a failure names the right claim), counts toward the 32-line cap, and a plan that does not fit is refused, never trimmed. A failed claim means no confirm, the armed rollback restores the router, and the apply result carries `failed_claim`. A lab device without
`lab = true` needs approval for every change. The design-time formulas in `03` (plan_hash) and `04` (risk matrix,
approvals) predate this ADR; where they differ, this ADR and `mcp/newton_mcp/plan.py` `PLAN_HASH_FIELDS` govern.

## ADR-019 — Owner approval in the client, proven by a secret the agent lacks
**Status:** Accepted, 2026-10-27 (the maintainer). Proposed 2026-10-24 (revised after the maintainer's interactive test the same day; the maintainer: "loud approvals, loud double checks", passphrase default with an
authenticator option, scoped easy mode). Replaces ADR-018 item 6 (terminal-only approval). Amends design hard rule 5.
**Context:** ADR-018 sent every approval to `newton-approve` in a terminal. The maintainer wants to approve inside the client. A test
measured Claude Code 2.1.303: a headless `claude -p` cancels an elicitation in under 10 ms in every permission mode, but
an Elicitation hook (user, project or `--settings`) answers Accept in 10 ms with any content and a server cannot tell it
from a human; `bypassPermissions` lets an agent write that hook file; and the owner's account may launch the MCP server
itself (the sudoers rule), so a process can answer its own elicitation. A bare Accept is therefore not proof of a human.
**Decision:**
1. A secret the agent does not hold rides inside the dialog. Level `passphrase` (default): the owner's existing
   approval passphrase, checked with `derive_k` against the stored fingerprint and never stored. Level `totp`
   (offered at setup, enrolled only in the owner's terminal): a 6-digit code against a seed in a newton-owned 0600 file,
   single use. A bare Accept proves nothing and is never accepted.
2. Order: `newton_plan_change` stages and returns the real diff; the agent shows it to the owner in chat and the owner
   says yes (`owner_confirmed_in_chat`, ADR-018 item 1); `newton_apply_change` then raises ONE dialog built by Newton from
   the stored plan (banner, facts, what can break, undo time), with the agent's explanation after it as unchecked claims.
   Both confirmations are about the same staged diff. The dialog appears only inside apply.
3. Hard rule 5 reads: no MCP tool takes an approval from the agent. The server may collect one from the human through
   client elicitation inside `newton_apply_change`; the agent supplies no approval input and no tool parameter can carry one.
4. The first approval on a device carries a warning; the acknowledgement is stored after the first successful approval.
   (Amended 2026-10-30: the warning no longer asks for the device name to be typed. In the owner's live test the
   extra field pushed the answer past the time limit, and the passphrase is the proof either way. What is given up: the
   name was typed once per device, so it never guarded later approvals; an owner who reuses one passphrase on several
   routers now relies on the device name in the dialog's title line on the first approval too.)
5. Wrong answers are counted in a file under the newton state directory (3 misses lock 5 min, doubling to 24 h), so
   relaunching the server does not reset them. An answer that arrives in under 1.5 s is treated as automatic, not as a person.
6. Any client that cannot show the dialog, cancels at once, answers too fast, or is locked falls back to `newton-approve`,
   which is unchanged. The token, plan hash, expiry clamp, single use and the router's check are the same as before.
7. The lab carve-out stays (ADR-018 item 6).
8. Scoped grants (the owner allows named kinds of change on a device until a time, opened with the secret, ended by any
   non-CONFIRMED result) and the `NEWTON RESULT` notice extend this ADR. A plan inside a live grant skips
   the chat confirmation of item 2 (the maintainer, 2026-10-24); Newton still shows the diff and the loud result line. A plan
   outside every grant, and every HIGH plan, keeps both confirmations. HIGH needs a second dialog every time.
9. The wait is bounded (180 s; 60 s before 2026-10-30). With no answer Newton cancels and says that the dialog timed out,
   that nothing was approved, that an answer typed later is ignored even if the dialog is still on the screen, and to
   ask for the change again or run newton-approve <id>. The same text covers an owner who walked away.
10. The passphrase field is shown as typed (measured: plain text, no masking). After a passphrase approval Newton
   returns a one-line notice to clear the screen and scrollback; the agent relays it once per session. Newton never
   echoes an answer back in a result, audit line or log. The default proof stays the passphrase; the TOTP option is
   offered at setup; the default lives in one constant (`approval_proof.DEFAULT_LEVEL`).
**Known limits (measured, Claude Code 2.1.303):** the dialog is shown in the terminal that runs Claude Code, waits for
the person, and is not skipped under `bypassPermissions`. In the remote-control phone app it is NOT rendered, so a
session driven only from that app looks stuck until the time limit (60 s, 180 s since 2026-10-30) and then returns the notice of item 9; remote
owners answer in the terminal or use `newton-approve`. The normal path is an owner at the machine running Claude Code.
**Consequences:** the typed passphrase passes through the client process: it lands in `~/.claude/debug` when Claude
Code debug logging is on, and an installed hook could read it. `newton-doctor` warns about debug logging, and `newton-enrol rotate`
replaces a passphrase. The `totp` level avoids this because a captured code is worthless a minute later. The managed-settings guard (Claude Code hooks locked to managed) is offered by the first
install as a question, default no, because it also stops the owner's own Claude Code hooks; without it `newton-doctor`
reports the guard INCONCLUSIVE and says the trade-off. Upgrades never write it (the maintainer, 2026-10-27). The debug-log
exposure is accepted for 1.0 and listed in `SECURITY.md` under Known limits (the maintainer, 2026-10-27). The
form field is not masked (measured). Approval authority is still the owner's secret.

## ADR-020 — Accepted risks for 1.0: no rate limit, fingerprint guess oracle
**Status:** Accepted, 2026-10-26 (the maintainer: "Go with your recommendations", on findings APR-03 and S-9 from the pre-release security review).
**Context:** `04` promised a per-device rate limit on applied changes (APR-03), and placeholder fingerprints
(HMAC-SHA256 of path and value, 8 bytes) let a model test a guess for a low-entropy secret by planning it and
comparing the fingerprint with the current one, one SSH stage per guess (S-9).
**Decision:** 1.0 ships without either control. APR-03: every production change already needs the owner's approval
(ADR-018), so a burst of changes needs a burst of approvals. S-9: an empty plan diff already answers "is the value
equal" without fingerprints, so removing fingerprints would not close the oracle; secrets that matter should be
high-entropy.
**Consequences:** `04` no longer lists a rate limit as built. Revisit APR-03 with scoped grants, which let
changes run without a fresh approval each time.

