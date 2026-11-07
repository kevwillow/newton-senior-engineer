# 05 — Device Abstraction Layer & Vendor Strategy

## Goal

Make "any network device" tractable by (1) a small adapter contract, (2) capability flags the policy
engine reasons about, (3) support **tiers**, and (4) a **certification suite** every platform must pass
in the virtual lab before writes are enabled. Knowledge (skills, ledger) layers on top; it never
substitutes for certification.

---

## Adapter contract (Python, illustrative — finalize in P0/P1)

```python
from enum import Flag, auto
from typing import Protocol

class Capability(Flag):
    STRUCTURED_STATE        = auto()  # state via structured API (ubus/NETCONF/gNMI/JSON), not screen-scrape
    CANDIDATE_CONFIG        = auto()  # stage changes before activation
    CONFIG_REPLACE          = auto()  # full replace supported
    NATIVE_COMMIT_CONFIRMED = auto()  # device-native timed revert (Junos, SR Linux, ...)
    DEVICE_SIDE_ROLLBACK    = auto()  # native OR NEWTON guard; REQUIRED for any write
    ROLLBACK_SURVIVES_REBOOT= auto()  # revert still happens if device reboots inside the window
    REVERT_IS_DISRUPTIVE    = auto()  # revert implies reboot/outage (e.g. FortiOS cfg-save revert)
    ATOMIC_APPLY            = auto()  # all-or-nothing activation
    STATIC_VERIFIER         = auto()  # e.g. Batfish supports this platform
    TWIN_AVAILABLE          = auto()  # a virtual replica exists in the lab
    OOB_CONSOLE             = auto()  # from inventory: console + power reachable

class Adapter(Protocol):
    platform: str
    def capabilities(self) -> Capability: ...
    async def facts(self) -> "Facts": ...
    async def get_config(self, scope: str | None = None) -> "ConfigSnapshot": ...   # raw + structured + hash
    async def get_state(self, getter: str, **params) -> "StateResult": ...          # allowlisted getters only
    async def render_plan(self, ops: list["Op"], base: "ConfigSnapshot") -> "RenderedPlan": ...
    async def lint(self, plan: "RenderedPlan") -> list["Finding"]: ...
    async def arm(self, txn: "Txn", timeout_s: int) -> "ArmReceipt": ...           # LKG + device-side timer
    async def apply(self, txn: "Txn") -> "ApplyReceipt": ...
    async def verify_mgmt(self, txn: "Txn") -> "CheckResult": ...                  # MUST open a NEW session
    async def effect_checks(self, txn: "Txn") -> list["CheckResult"]: ...
    async def confirm(self, txn: "Txn") -> None: ...
    async def rollback(self, txn: "Txn") -> "RollbackReceipt": ...
    async def pending(self) -> "PendingState": ...                                 # device-side truth for reconciliation
```

Design notes:
- The contract deliberately mirrors NAPALM's candidate/commit/confirm/rollback model
  (`commit_config(revert_in=…)`, `has_pending_commit()`, `confirm_commit()`, `rollback()`) [V-26] so
  NAPALM-supported platforms get a thin wrapper.
- `verify_mgmt` must not reuse the session that applied the change — reuse hides lockouts [V-04].
- `pending()` is what lets `newtond` reconcile after a crash without trusting its own memory.

## Policy gates on capabilities

| Requirement | Rule |
|---|---|
| Any write | `DEVICE_SIDE_ROLLBACK` present **and** platform certified for the device's OS version range |
| Writes in `prod` | Also `ROLLBACK_SURVIVES_REBOOT`, or a human-approved exception |
| CRITICAL risk on `REVERT_IS_DISRUPTIVE` platforms | Change window + approval always, any profile |
| Lab CRITICAL auto-approve | `OOB_CONSOLE` healthy (console reachable + power control responding) |
| HIGH+ on platforms without `STATIC_VERIFIER` | Twin-first apply required if `TWIN_AVAILABLE` |

---

## Transports and libraries (pin exact versions in P0)

| Transport | Library | Use |
|---|---|---|
| OpenWrt rpcd JSON-RPC (`/ubus`) | `httpx` (async) | Primary OpenWrt path [V-17] |
| SSH | `asyncssh` (or Scrapli) | OpenWrt shim; read-only CLI tier on other platforms |
| NETCONF | `ncclient` / Junos PyEZ | Junos, IOS-XE/XR where enabled |
| gNMI | `pygnmi` | SR Linux, EOS, XR (state + config) |
| Vendor REST | `httpx` | FortiOS, EOS eAPI |
| Multi-vendor drivers | NAPALM (+ community drivers such as `napalm-srlinux`) | Candidate/commit/confirm on supported platforms [V-26] |
| CLI parsing (T0 only) | TextFSM + ntc-templates, Genie | Structured output from show commands |
| Serial | `pyserial` via ser2net TCP | OOB console |

Prefer model-driven interfaces (NETCONF/YANG, gNMI/OpenConfig, vendor JSON APIs) over screen-scraping.
The LLM is never the parser for anything a policy decision depends on.

---

## Support tiers

| Tier | Meaning | Write policy |
|---|---|---|
| **T0 Observe** | Reachable, read-only getters certified | No writes ever |
| **T1 Managed write** | Non-disruptive device-side rollback; certified | Writes per profile matrix |
| **T2 Managed write with caveats** | Revert is disruptive (reboot), coarse (minute granularity), or session-scoped | Approval required for MED+ in every profile; change windows for HIGH+ |
| **T3 No safe write path** | No revert mechanism NEWTON can rely on | Read-only; humans do writes |

A device's effective tier = min(platform tier, version certified?, OOB/twin availability).

---

## Platform matrix (initial — every row is provisional until certified)

| Platform | Transport | Revert primitive | What we know | Target tier |
|---|---|---|---|---|
| **OpenWrt 25.12** | rpcd JSON-RPC; SSH shim; serial | rpcd `uci apply {rollback,timeout}` + `confirm` [V-14, V-16]; NEWTON guard for reboot-safety [ADR-006] | Mechanism exists; CLI usage underdocumented [V-15]; an rpcd rollback does not survive a reboot (the change stays) [LVR-02]; the guard covers a reboot in installed mode | **T1** (after P3) |
| **Juniper Junos** (vJunos-router) | SSH CLI (NETCONF after 1.0) | `commit confirmed N comment newton-pending`; abort only while Newton's tagged commit is pending | Built; 8 lab shapes pass on vJunos-router 26.2R1 | **T1** (tested in the lab on a virtual image) |
| **Nokia SR Linux** | JSON-RPC / gNMI / `napalm-srlinux` | commit-confirm via `revert_in`; pending state visible device-side [V-26] | Community NAPALM driver advertises full candidate workflow | T1 |
| **Arista EOS** (cEOS) | eAPI / NAPALM `eos` | NAPALM `revert_in` (EOS mechanics to verify) | Generic NAPALM API verified; EOS specifics [LVR-17] | T1 |
| **Cisco IOS-XR** (XRd) | NETCONF / gNMI / NAPALM | commit confirmed | [LVR-17] | T1 |
| **Cisco IOS-XE** | SSH / NETCONF / NAPALM `ios` | NAPALM `revert_in` requires `archive`; minute granularity [V-26] | Caveats documented | T2 |
| **FortiOS** (FortiGate VM) | REST / SSH | `cfg-save revert` + `cfg-revert-timeout` → **reboots** to saved config [V-27] | Disruptive; docs disagree across products [V-27] | T2 |
| **MikroTik RouterOS** (CHR) | SSH CLI | scheduler + `/system backup load`: undo is a reboot into the backup; window = max(timeout, 120) s | Built; 8 lab shapes pass on CHR 7.24.5 | **T2** (tested in the lab on a virtual image) |
| **VyOS** | SSH CLI | `commit-confirm` in `action reload` mode only; Newton refuses other devices and prints `set system config-management commit-confirm action reload; commit; save` | Built; 8 lab shapes pass on VyOS 2026.10 | **T1** (reload mode only) |
| **Linux + FRR** | SSH | NEWTON guard pattern (same as OpenWrt) | Design reuse | T1 (later) |
| Ubiquiti, TP-Link Omada, etc. | varies | unknown | — | T0 until certified |

Vendor change text is data and is tokenised: VyOS verbs are `set`, `delete`, `comment`; RouterOS and
Junos use allow lists of full lowercase menus or hierarchies (abbreviations and case variants are refused); the
names `newton-*` and the text `NEWTON-` are reserved.

Static verification: Batfish supports Arista, Cisco, Juniper, Fortinet, Palo Alto, Check Point,
Cumulus, F5, SONiC, A10, AWS, Azure — not OpenWrt or MikroTik [V-28].

Virtual images: containerlab supports OpenWrt, cEOS, vJunos-router, Cisco IOL/XRd, SR Linux,
FortiGate, MikroTik, VyOS, FRR, SONiC among its kinds [V-25]. Image licensing/EULAs vary by vendor —
check each before use, and never redistribute images [LVR-16].

---

## Certification suite (per platform × OS version range)

A platform is **certified** for a version range when all of these pass in the lab, recorded as ledger
entries (`08`):

| ID | Test | Pass criteria |
|---|---|---|
| CS-01 | Getters | Every allowlisted getter returns schema-valid data on twin and (if present) hardware |
| CS-02 | Snapshot stability | Two consecutive snapshots of an idle device have identical hashes |
| CS-03 | Deterministic render | Same ops + same base → byte-identical rendered diff |
| CS-04 | Lint corpus | Known-bad fixtures for this platform are all rejected |
| CS-05 | Happy path | arm → apply → verify → confirm; post-state matches intent; no pending state left |
| CS-06 | Withheld confirm | Device reverts by itself within timeout + tolerance |
| CS-07 | Controller crash | Kill `newtond` after APPLIED → device reverts; restart reconciles to DEVICE_REVERTED |
| CS-08 | Mgmt lockout | Change that cuts mgmt access → device reverts; mgmt restored |
| CS-09 | Reboot in window | Behavior measured and recorded → sets/clears `ROLLBACK_SURVIVES_REBOOT` |
| CS-10 | Redaction | All platform secret fields in fixtures redacted; placeholders round-trip as "keep" |
| CS-11 | Injection fixtures | Attacker-controlled fields enveloped; no policy-relevant behavior change |
| CS-12 | Idempotency + drift | Re-applying a confirmed plan → no-op; out-of-band edit between plan and apply → STALE |

---

## Onboarding a new platform (procedure)

1. Create the skill stub `skills/newton-<platform>/SKILL.md` (no secrets, no addresses).
2. Add the platform's twin image to the lab (containerlab kind or Proxmox VM) and a probe topology.
3. Implement the adapter — or wrap NAPALM — implementing the contract above.
4. Write platform lint rules + fixtures (start from known silent-failure modes).
5. Run the certification suite; record each result as a ledger entry with evidence.
6. Assign a tier; enable writes for `lab` profile only.
7. Add NEWTON-Bench tasks for the platform; run cross-model.
8. Only after ≥ N clean bench runs and a human review: allow `staging`, then `prod`.

## Prioritization of platforms after OpenWrt [OPEN — decide in P7]

Pick platform #2 to *prove the abstraction*, not for market reach: it should have a native
commit-confirm, a structured API, a container or light VM image, and acceptable licensing.
Candidates: **Nokia SR Linux** (container, JSON-RPC/gNMI, NAPALM community driver), **Arista cEOS**
(container, eAPI, NAPALM core driver), **Juniper vJunos-router** (VM, NETCONF, best-known commit
confirmed). Decide using [LVR-16] licensing results and your Proxmox resource budget.
