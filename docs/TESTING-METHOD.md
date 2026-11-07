# Testing method

How Newton proves a change is safe, and what "safe" means at each layer.

The single rule behind everything below: **a safety claim without a test that failed
before the change and passes after it is treated as false** (`docs/design/09-LAB-AND-TEST-STRATEGY.md`, the opening rule).
Three layers of tests run in three different environments and check three different
kinds of failure. Together they are the gate.

## 1. Layers

| Layer | Where it lives | How to run it |
|---|---|---|
| Unit (per component) | `mcp/tests/` (`test_installed_layout.py`, `test_apply_check.py`, `test_approval_crypto.py`, `test_redact.py`, `test_probes_host.py`, ...), `tests/profiles/`, `tests/protocol/`, `tests/serial/` | `mcp/.venv/bin/python -m pytest <test>/ -q` |
| On-router programs | `device/openwrt/newton-router/tests/` (the `newton-router` grammar, txn, probes, seal, confirm, abort), `device/openwrt/newton-guard/tests/` (the guard) | `mcp/.venv/bin/python -m pytest device/openwrt/newton-router/tests -q`; same for the guard |
| Live lab | `lab/newton-lab-test.py` reads `lab/lab.toml` and every `lab/scenarios/*.toml` and `lab/scenarios/openwrt/*.toml` | `python3 lab/newton-lab-test.py --list` (no lab); `python3 lab/newton-lab-test.py --only <name>` (touches the real virtual lab) |

`lab/lab.toml` is your own lab file and is not in this repository: it names your
hypervisor, the lab VMs and the key and token files.
`lab/lab.example.toml` is the template: the same tables and the same keys with
synthetic values (made-up hosts, documentation-range addresses, synthetic VM ids and
placeholder paths under `/home/user/`). Copy it, fill in your own values and point
the runner at the copy (`--lab <file>`); `lab/pulsar.example.toml` is the same idea
for the physical Pulsar lab.

Unit and contract tests never touch the network; the live lab requires the lab lock
(`docs/design/09-LAB-AND-TEST-STRATEGY.md`, the lab-access rules). Real device captures may carry
secrets and live outside git (`docs/design/09-LAB-AND-TEST-STRATEGY.md`, the same section).

## 2. The scenario contract

A scenario is one TOML file. Each one declares its inputs and the expected outcome,
and the runner drives every probe in the order the contract requires
(the module docstring of `lab/newton-lab-test.py` and `run_scenario`, the per-scenario run order).

| Field | What it means |
|---|---|
| `expect` | The terminal outcome the runner must observe. One of `confirmed`, `rolled_back`, `rejected`, `refused`, `noop`, `none` (the module docstring of `lab/newton-lab-test.py`). |
| `regression` | A list of checks that MUST pass before and after a confirmed apply. The string `"default"` expands to `[regression].default` in `lab/lab.toml` (e.g. `mgmt_ssh`, `mgmt_luci`, `client_internet`, `client_dns`, `client_dhcp`, `portfwd`). |
| `breaks` | Checks that must PASS before a change and FAIL after a confirmed apply. The break is the proof the change took effect on the wire. Example: `ow-fw-01-wan-input-drop.toml` names `wan_closed_refused` (a closed tcp port on the WAN address stops being refused when the zone goes to `DROP`). |
| `effect` | A check that must FAIL before and PASS after a confirmed apply. Used to assert a specific live state the change creates. Two effects in `ow-fw-01-wan-input-drop.toml` prove the input chain ends in `jump drop_from_wan` and that both WAN addresses stop answering on a closed port. |
| `probes` | Sealed probes the plan reads from a TAB-joined file (`_parse_probes` in `lab/newton-lab-test.py`). Caps: 32 lists, 128 bytes/field, 4096 bytes total (`MAX_PROBES`, `MAX_PROBE_FIELD`, `MAX_PROBES_BYTES`). |
| `setup` / `cleanup` | Steps from `[steps.*]` in `lab/lab.toml` that run before the apply and (in a `try/finally`) after the run. Each must exit 0 (`run_step` in `lab/newton-lab-test.py`). |
| `reject_match` / `refuse_match` | A regex the runner pins WHY a plan or apply was refused. Required when `expect = "rejected"` or `expect = "refused"`; forbidden otherwise (the module docstring of `lab/newton-lab-test.py` and `validate_scenarios`). |
| `approval` | `true`, `"none"`, or `"wrong"`. The runner mints (or mints-and-flips) a token, or sends none; "wrong" forces the router to refuse the apply (the module docstring of `lab/newton-lab-test.py`). |

The order of operations for one scenario is: reset, resolve `{var}` placeholders,
setup, BEFORE probes (regression + breaks must pass, effects must fail), plan,
classify the outcome (`classify_apply` in `lab/newton-lab-test.py`), AFTER probes (on `confirmed`: regression
still passes, breaks fail, effects pass; on other outcomes: regression still passes, breaks still pass and effects must
fail), `post` checks, cleanup. A probe that times out is a normal failed result; a
step, plan or apply that times out is an ERROR (the module docstring of `lab/newton-lab-test.py`).

## 3. Snapshot resets and why

Every scenario starts from a known state. The runner rolls each `[devices.<name>]`
in the scenario's `reset = [...]` list back to the hypervisor snapshot named in
`[devices.<name>].snapshot` (`lab/lab.toml` for the OpenWrt profile devices).
The function is `pve_reset` (`lab/newton-lab-test.py`); it calls
`pve_rollback` and waits for the hypervisor
task to stop. On the lock error `can't lock file` (the previous VM's `qm cleanup`
holds the VM config lock for about 35 s), it retries up to `RESET_MAX_ATTEMPTS = 4` times,
`RESET_RETRY_SLEEP_S = 12` apart (`RESET_MAX_ATTEMPTS`, `RESET_RETRY_SLEEP_S`). Every attempt
is appended to the rec list in `pve_reset` so a later failure
leaves the earlier records behind.

After a reset the runner waits for ssh to be ready, runs `router_hello_preflight`
in the key lane (`router_hello_preflight` in `lab/newton-lab-test.py`, requires the four sha256
fields `prog`, `helper`, `guard` and `init` of the on-router program, helper
and guard to match the controller's files, and `guard-state=idle`), then `wait_settled` waits until a
configurable boot fingerprint is unchanged for `settle.quiet_s`
(`lab/lab.toml`, `wait_settled` in `lab/newton-lab-test.py`). Without these, the
first probes can race the boot.

## 4. Planted defects

The on-router programs (`newton-router`, `newton-guard`) carry their own
defect-injection suite. A planted defect is a one-line mutation of the program
that a plausible bug would introduce, paired with the exact pytest path that
must catch it. The lists live in `device/openwrt/newton-router/tests/planted/
defects_*.py` (`defects_apply.py`, `defects_leash.py`, `defects_probes.py`,
`defects_txn.py`, ...). The runner at
`device/openwrt/newton-router/tests/planted/runner.py` mutates the program,
runs the listed tests, and prints one row per defect: `ID KILLED|SURVIVED|STALE
first-failing-test description`. A defect that `SURVIVED` is a coverage hole.

Two quick gates guard the lists silently going stale:
`device/openwrt/newton-router/tests/test_planted_defects_current.py` checks every
defect's `old` text is unique in the program, that `old != new`, that every test
path exists, that no defect id is duplicated across files, and that the total
count is at least 200 (`test_planted_defects_current.py`, its module docstring and the `total < 200` check).

The lab side has its own form of planted defect: a hand-applied fault on the
router, with the exact probe command that must catch it. The lab walks every default
regression check, plants the matching fault (a stopped service, a missing
firewall rule, a closed port), and shows the same check failing under the fault
and passing again after the fix. The same discipline covers effects: the
planted-faults run showed the
01 effect 1 (listener probe) exiting 1 on the baseline and fail-open state, and
exiting 0 only after `Interface='lan'` is in place.

## 5. The installed-layout lesson

A code path that works in development can be wrong once installed. The dev venv
is an editable install (a `.pth` file points at the repo), so file paths resolve
under the repo tree even when the running code lives under site-packages. That
hides shipping bugs.

The concrete instance: an installed `newton-mcp` used to look for its profile
files next to the Python package, a path that does not exist once the package
moves under site-packages (see the module docstrings of `mcp/tests/test_installed_layout.py` and
`mcp/tests/test_manifest_path_home.py`). The fix was to follow
`NEWTON_HOME`; the regression test is `mcp/tests/test_installed_layout.py`,
which builds a SECOND venv with `uv` from the local repo, installs it
NON-editable, gives it its own `profiles/` tree under `NEWTON_HOME`, and runs
the probes from `cwd=tmp` (not the repo), `HOME=<tmp>`, no `PYTHONPATH`, no
`NEWTON_MANIFEST` (`mcp/tests/test_installed_layout.py`). The answer is the
answer an end-user sees, never the dev venv's. The CHANGELOG records this as
v0.3.1 (the v0.3.1 entry of `CHANGELOG.md`).

Rule for new code: if the code resolves a path or reads an environment that
might differ between a checkout and a `pip install` site-packages tree, a test
must exercise the installed form, not just the dev venv.

## 6. The gate

The gate is the union of every suite above. Counts are quoted from a fresh run,
never from a list frozen in a README; `--collect-only` is the floor, a full run
is the truth.

| Suite | Path | How |
|---|---|---|
| Lab runner (unit tests of the runner) | `lab/tests/` | `mcp/.venv/bin/python -m pytest lab/tests -q` |
| Serial | `tests/serial/` | `mcp/.venv/bin/python -m pytest tests/serial -q` |
| Protocol | `tests/protocol/` | `mcp/.venv/bin/python -m pytest tests/protocol -q` |
| Profiles | `tests/profiles/` | `mcp/.venv/bin/python -m pytest tests/profiles -q` |
| Guard | `device/openwrt/newton-guard/tests/` | `mcp/.venv/bin/python -m pytest device/openwrt/newton-guard/tests -q` |
| Router | `device/openwrt/newton-router/tests/` | `mcp/.venv/bin/python -m pytest device/openwrt/newton-router/tests -q` |
| MCP server | `mcp/tests/` | `(cd mcp && uv run --extra test pytest -q)` |
| Live lab | `lab/newton-lab-test.py` over `lab/scenarios/*.toml` | `python3 lab/newton-lab-test.py --list` then `--only <name>` (or the whole set; results land in `lab/.results/`, gitignored) |

Every count change must be explained in the PR: which scenario or test was
added, why, and the ID that pins it (test IDs live in
`docs/design/09-LAB-AND-TEST-STRATEGY.md` §3.1-3.5 and in the scenario files). Counts
that match without an explanation are a sign the gate is drifting.

## 7. What "verified" means, and what was NOT verified

A control or scenario is **verified** when its lab scenario passed in the
gate, meaning the outcome matched `expect`, every effect's BEFORE and AFTER
matched, every regression check stayed green, and the plan diff equalled the
batch line for line.
A scenario's description must say which side of the run proves what
(`ow-dns-04b-dnssec-full.toml:2` is the example: AD=1 only when dnsmasq-full
validates itself).

The "Pull request checklist" in `docs/design/AGENTS.md` carries the
line. Two hard rules (`docs/design/AGENTS.md`):

- Tests first. Write the failing test, reference its ID, then implement.
  Every behavioral change has a test. No exceptions for "small" changes. The rule
  names areas of the planned layout (some are not directories in the tree today)
  and the on-device guard (`docs/design/AGENTS.md`).
- No secrets or real device data in git. No credentials, real IPs/hostnames,
  Wi-Fi keys, or captured configs.

Every scene and every control test ends with a "Not verified" line that lists what
the scenario does NOT cover (a global Not verified list
for OpenWrt 25.12.5). The same discipline applies
per scenario (a "Not verified" note at the end of each
group). "Verified" is always about a specific run, on a specific commit,
with a specific scenario file and its description; never a general claim about
behaviour.

## 8. Adding a vendor

The contract is the same on every platform: stage, apply with a native timed
revert, verify over a fresh connection, confirm, abort, backup. The native
revert differs (VyOS `commit-confirm`, MikroTik Safe
Mode or a scheduled export revert, Junos `commit confirmed`, Arista `configure
session` + `commit timer`, FortiOS `cfg-save revert`, IOS XE `configure terminal
revert timer`). The lab runner, the scenario contract, the planted-defect
discipline and the gate do not.

Checklist for a new platform:

1. **Adapter.** Implement the seven verbs (read state, stage, apply with a
   timed revert, verify over a fresh connection, confirm, abort, backup) on the
   vendor's native protocol. The repo puts the
   OpenWrt side in `device/openwrt/newton-router/` and `device/openwrt/newton-guard/`,
   the MCP server in `mcp/newton_mcp/`, the host scripts in `scripts/` and the
   profile tree in `profiles/openwrt/`; the other vendors' adapters are in
   `mcp/newton_mcp/adapters/` and their profiles in `profiles/<vendor>/`.
   Match the OpenWrt side's safety surface (no shell string building, no creds in
   code, argv lists only).
2. **Reuse the runner.** Add a vendor block to `lab/lab.toml` (`[devices.<name>]`
   per device with the vmid, host, user, snapshot, settle fingerprint; see the
   OpenWrt profile blocks in `lab/lab.example.toml`). The runner's reset is
   hypervisor-specific: it calls `pve_rollback`
   and `pve_reset` (both in `lab/newton-lab-test.py`), so a second vendor
   whose lab devices run on the same hypervisor only needs a `[devices.<name>]`
   block with a hypervisor snapshot, the same shape as the existing blocks.
3. **First scenario shapes.** Seven scenarios, each one TOML file, in this order:
   (a) happy path (`expect = "confirmed"`), (b) management-address IP lockout
   (`expect = "rolled_back"`; mirrors `lab/scenarios/02-mgmt-ip-lockout.toml`),
   (c) management firewall drop (`expect = "rolled_back"`), (d) injection in a
   device string (`expect = "rejected"`), (e) bad syntax (`expect = "rejected"`,
   mirrors `lab/scenarios/05-bad-syntax.toml`), (f) service reachable after
   the change, (g) uplinks down with rollback. The seven are the minimum for the
   gate.
4. **Reuse checks, regressions, breaks, effects, planted defects.** A check is a
   probe that runs a single shell line against the device and matches a regex
   on its output (`_run` in `lab/newton-lab-test.py`). The runner cares nothing
   about the device's CLI; only the probe's exit code and stdout match.
5. **Reuse the planted-defect runner.** The repo's planted-defect runner lives
   at `device/openwrt/newton-router/tests/planted/runner.py` and the lists
   beside it (`device/openwrt/newton-router/tests/planted/defects_*.py`); where
   the second vendor's equivalent lives is a decision for Phase 4, and the repo
   does not fix it yet.
6. **Reuse the installed-layout test.** If the new adapter ships as part of an
   installable package, a non-editable install test must exercise the production
   layout, not the dev venv (`mcp/tests/test_installed_layout.py` is the
   pattern).
7. **Gate counts.** The PR adds one new row to §6 and explains every count
   change in the test path. A scenario with no planted defect that catches its
   own rollback is not a passing scenario.
8. **Lab isolation.** The vendor's lab device joins the same isolation rule:
   the lab bridges carry no uplink to the operator LAN, only the test runner
   reaches the device, and `scripts/newton-lab-isolation --iface <iface>
   --allow-mac <mac of the upstream router> --seconds N` passes
   (`scripts/newton-lab-isolation:1-7`).
9. **"Verified" and "Not verified".** Every scenario description carries the
   measured proof and its limits. Each vendor keeps its own "Not verified" list in the same shape.

The shape of "one vendor at a time" is the point: the test method is the
product. A new vendor's first seven scenarios prove the adapter; the rest of the
controls follow the same scenario contract, on the same runner, in the same
gate.