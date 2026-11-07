# 12 — Verification Ledger (research phase)

Everything the design depends on, with where it came from. Research date: 2026-10-06.
Paraphrased; follow the links for exact wording. Re-verify anything older than ~90 days before
relying on it, and re-verify version-specific items on every OS/SDK upgrade.

## Verified facts [V-nn]

| ID | Fact (paraphrased) | Source(s) | Limits / notes |
|---|---|---|---|
| V-01 | NetClaw: Apache-2.0 agent on OpenClaw, powered by Claude; ~670 stars/~186 forks at research time; `SOUL.md` lists 233 skills backed by 173 MCP servers; multivendor server read-only by default with write tools absent unless enabled; writes single-pathed per platform; prod changes gated on ServiceNow CR; GAIT audit trail; listed multivendor families don't include OpenWrt | github.com/automateyournetwork/netclaw · github.com/automateyournetwork/netclaw/blob/main/SOUL.md · sourcepulse.org/projects/26201661 | Counts change daily |
| V-02 | Juniper's official `junos-mcp-server` supports config changes with a commit-guardrails section; README warns to use it only where policy allows sending Junos data to LLM services; stdio + streamable HTTP | glama.ai/mcp/servers/Juniper/junos-mcp-server/tree · lobehub.com/mcp/juniper-junos-mcp-server | Read via directory mirrors of the README |
| V-03 | `shigechika/junos-mcp` push flow: lock → load → diff → commit check → commit confirmed → health check → confirm → unlock; auto-rollback on failure | glama.ai/mcp/servers/shigechika/junos-mcp/tools/push_config · pypi.org/project/junos-mcp/0.11.0/ | — |
| V-04 | `anderson-jason573/juniper-junos-mcp`: preview re-validated against device before commit; commit confirmed; reconnects on a new session to verify before confirming; model picks a tool, not a command; README warns its MCP endpoint has no authentication | glama.ai/mcp/servers/anderson-jason573/juniper-junos-mcp/tree | Community project, not Juniper |
| V-05 | Several OpenWrt MCP servers exist; reviewed READMEs state root SSH access (`s09x/openwrt_ssh_mcp`, `jsebgiraldo/openwrt_ssh_mcp`); `Necho-dev/openwrt-cli` ships a skill + FastMCP server with an `mcp.mode` guard; read-only ubus variants exist | github.com/s09x/openwrt_ssh_mcp · glama.ai/mcp/servers/@jsebgiraldo/openwrt_ssh_mcp · github.com/Necho-dev/openwrt-cli/releases/tag/v1.2.0 · images.glama.ai/mcp/servers/integrations/openwrt | No transactional rollback described in READMEs reviewed; code not audited |
| V-06 | `openwrt-iac/uapi` v2.4.0 (hardware-verified findings): ports silently dropped on port-less protocols (with `proto all` + port 22 + ACCEPT → bare accept-everything); zone `any` isn't a wildcard (only `*`); list-valued redirect matches discard the section; unresolvable nft protocol tokens reject the whole ruleset and the router keeps its previous firewall; netifd silently inert when a proto handler isn't installed; no way to ask the router in advance which sections will be refused | github.com/openwrt-iac/uapi/releases/tag/v2.4.0 | Re-implement behaviors; check license before reusing code |
| V-07 | Cisco expanded AgenticOps across its portfolio (Feb 10, 2026), including risk-aware validation of changes against live topology/config/telemetry with blast-radius analysis | prnewswire.co.uk/news-releases/cisco-expands-agenticops-innovations-across-portfolio-302683240.html (via bolsamania.com mirror) | Vendor marketing claims |
| V-08 | Forward Networks announced Forward AI (Jan 29, 2026) on its digital twin, exposed via MCP; Forward Predict runs proposed changes against the twin before production, exposed via REST/MCP | forwardnetworks.com/blog/2026/01/29/introducing-forward-ai/ · networkworld.com/article/4175696 | Vendor claims |
| V-09 | HotNets 2023 (Mondal et al.): GPT-4 alone produced egregious topology/syntax/semantic errors; verifier-in-the-loop (Batfish + semantic checks) gave ~10× / ~6× leverage | arxiv.org/abs/2307.04945v1 · conferences.sigcomm.org/hotnets/2023/papers/hotnets23_mondal.pdf | Older model generation |
| V-10 | ETH Zürich, AIWILD @ ICML 2026 (arXiv 2606.06212): SOTA models fail at scale and introduce new errors; agentic + verifier improves efficacy ~12% and safety ~17% on average; GPT-5 mini regressions 13.3% (single-shot) → 0.9% (agentic + verifier, 20 steps); benchmarks CORNETTO, NetArena, NIKA; cites hyperscaler deployments NetAssistant, BiAn, Confucius | alphaxiv.org/abs/2606.06212 | Models tested: GPT-5 mini, GLM-4.7, Qwen3.5-9B, Gemma 4 E4B |
| V-11 | NetInjectBench (arXiv 2607.10490): indirect prompt injection via tickets/alerts/logs/runbooks/ChatOps; patterns include fake approval, fake emergency, fake vendor authority, poisoned runbook; concludes network-ops agents need execution-time authorization boundaries | alphaxiv.org/abs/2607.10490 · arxiv.org/pdf/2607.10490 | — |
| V-12 | Multi-agent injection threat model (arXiv 2609.22949): indirect injection via tool outputs succeeded 43% of attempts; four architectural defenses cut overall success 31.2% → 4.2%; privilege-scoped tool access eliminated privilege escalation | arxiv.org/pdf/2609.22949 | Their test system, not network-specific |
| V-13 | OpenWrt 25.12.0 (early March 2026): `apk` replaces `opkg`; dropbear 2025.89; kernel 6.12.71; attended sysupgrade/`owut` included; shell history in RAM; >2200 devices; 24.10 security support ended Sept 2026 | forum.openwrt.org/t/openwrt-25-12-0-stable-release/247228 · helpnetsecurity.com/2026/03/09/openwrt-25-12-0-released/ · heise.de/-11204407 · openwrt.org/releases/25.12/notes-25.12.0 | Check current 25.12.x point release |
| V-14 | rpcd exposes ubus `uci` methods including `apply {rollback, timeout}`, `confirm`, `rollback`; the wiki says this section is severely outdated/incomplete | openwrt.org/docs/guide-developer/ubus/uci | Exact semantics → LVR-01 |
| V-15 | Forum: `ubus call uci apply '{"timeout":30,"rollback":true}'` from CLI → "Invalid argument"; with a session added → "no response"; no resolution posted | forum.openwrt.org/t/how-to-use-uci-apply-from-ubus/95192 | 2021/2023 posts |
| V-16 | LuCI moved to an rpcd-based apply/rollback workflow requiring explicit confirm; on timeout the config reverts; the luci-lua-runtime model enforces a ≥ 90 s timeout | git.openwrt.org/project/luci (atom feed) · git-03.infra.openwrt.org/project/luci/tree/modules/luci-lua-runtime/luasrc/model/uci.lua · openwrt.github.io/luci/jsapi/LuCI.uci.html | rpcd's own minimum unknown |
| V-17 | rpcd ACLs: roles in `/usr/share/rpcd/acl.d/*.json` (ubus objects/methods, uci configs, file paths); users in `/etc/config/rpcd` (`$p$user` uses `/etc/shadow`, `list read/write <role>`); least-privilege user pattern with ACL persisted via `/etc/sysupgrade.conf`; `apk add rpcd-mod-file uhttpd-mod-ubus` | openwrt.org/docs/techref/ubus · home-assistant.io/integrations/ubus/ | Method names → LVR-03 |
| V-18 | Dropbear `authorized_keys` options: `command=`, `restrict`, `no-port-forwarding`, `no-agent-forwarding`, `no-X11-forwarding`, `no-pty`, `permitopen`, `permitlisten`; `SSH_ORIGINAL_COMMAND` set for forced commands | man.archlinux.org/man/dropbear.8 | OpenWrt build options → LVR-04 |
| V-19 | `fw4 check` tests the rendered ruleset with nftables check mode without applying; `fw4 restart` checks before restarting | lxr.openwrt.org/source/firewall4/root/sbin/fw4 · git.openwrt.org/project/firewall4 | — |
| V-20 | MCP 2026-07-28: stateless (no initialize; `server/discover`); no protocol sessions — cross-call state via server-minted handles in tool args; MRTR (`input_required`) replaces server-initiated elicitation/sampling/roots; tasks moved to an extension; sampling/roots/logging deprecated; deterministic `tools/list` order recommended | modelcontextprotocol.io/specification/2026-07-28/changelog | — |
| V-21 | MCP Python SDK v2.0.0 stable supports 2026-07-28 and earlier revisions from one server; FastMCP 4 stable on SDK v2 (`ctx.elicit()` old-protocol-only; tasks in `fastmcp-tasks`) | github.com/PrefectHQ/fastmcp/releases/tag/v4.0.0 · gofastmcp.com/development/v4-notes · github.com/commit-check/commit-check-mcp/pull/25 (quotes SDK v2.0.0 notes) | Pin versions in P0 |
| V-22 | `mcp-odoo` v1.3.0 implements era-portable write confirmation: MRTR for modern clients, legacy elicitation for older ones, approval-token fallback | github.com/erpipe-org/mcp-odoo/releases/tag/v1.3.0 | Pattern reference only |
| V-23 | Agent Skills open standard (agentskills.io, Dec 2025); SKILL.md + optional scripts/references/assets; progressive disclosure; Claude Code `.claude/skills/`, OpenCode `.opencode/skills/` and `~/.config/opencode/skills/`; OpenCode discovers Claude-compatible paths | agentskills.io/specification · github.com/irarainey/agent-plugins · codex.danielvaughan.com/2026/05/05/agent-skills-open-standard-portable-skills-codex-cli-cross-agent/ | — |
| V-24 | Claude Code hooks: `PreToolUse` can return `permissionDecision` allow/deny/ask; matchers are regex on tool name; MCP tools named `mcp__<server>__<tool>`; any deny blocks | code.claude.com/docs/en/Hooks · code.claude.com/docs/en/agent-sdk/hooks | Behavior on your version → LVR-15 |
| V-25 | containerlab kinds include OpenWrt (VM), Arista cEOS, Juniper vJunos-router/switch, Cisco IOL/XRd/others, Nokia SR Linux, FortiGate, MikroTik RouterOS, VyOS, FRR, SONiC | containerlab.dev/manual/kinds/ · containerlab.dev | Image licensing → LVR-16 |
| V-26 | NAPALM: `commit_config(revert_in=…)`, `has_pending_commit()`, `confirm_commit()`, `rollback()`; IOS driver needs `archive` and works in whole minutes; `napalm-srlinux` supports commit-confirm via `revert_in` with device-side pending state | napalm.readthedocs.io/en/latest/tutorials/changing_the_config.html · napalm.readthedocs.io/en/latest/base.html · github.com/napalm-automation/napalm/commit/ec15b3d · pypi.org/project/napalm-srlinux/ | Per-platform mechanics → certification |
| V-27 | FortiOS `cfg-save revert` + `cfg-revert-timeout` (default 600 s); `execute cfg save` commits; revert happens by rebooting to the saved config; old forum report of batch-mode incompatibility (5.2); FortiProxy 2.0 reference describes revert mode as *saving* changes after idle, contradicting the FortiGate reference | docs.fortinet.com/document/fortigate/6.0.6/cli-reference/846611/cfg-save · community.fortinet.com (tech tip 93653) · docs.fortinet.com/document/fortiproxy/2.0.12/cli-reference/181920 · community.fortinet.com/t5/Support-Forum/…/m-p/45125 | Verify on current FortiOS |
| V-28 | Batfish supported config formats: A10, Arista, AWS, Azure, Cisco, Check Point, Cumulus, F5, Fortinet, Juniper, Palo Alto, SONiC (no OpenWrt/MikroTik) | batfish.readthedocs.io/en/latest/formats.html | — |
| V-29 | Asus RT-AX1800S v2 = RT-AX57M hardware (MT7981B, 256 MB RAM, 128 MB SPI-NAND, MT7531); OpenWrt support from 25.12.0; UART 3.3 V 115200 8N1, silkscreened, don't connect VCC; recovery via Asus Firmware Restoration rescue mode; U-Boot serial menu offers write-to-flash via serial | techinfodepot.shoutwiki.com/wiki/ASUS_RT-AX1800S_v2 · forum.openwrt.org/t/openwrt-support-for-asus-rt-ax57m-ax1800s-v2/208534 | Wiki + forum sources |
| V-30 | Published adversarial test suites seed SSIDs/device strings with delimiter-escape payloads (e.g. closing an "untrusted output" tag then `SYSTEM`), confirming wrapper tags alone aren't a boundary | pkg.go.dev/github.com/xunholy/promptzero@v0.771.0/test/adversarial | Pattern reference |

## Lab Verification Required [LVR-nn]

| ID | Hypothesis / unknown | Closed by | Phase | Status |
|---|---|---|---|---|
| LVR-01 | rpcd apply-with-rollback flow over JSON-RPC: which session must `confirm`; accepted timeout range; behavior when the reload drops the HTTP connection | SPK-1 | P0 | open |
| LVR-02 | rpcd rollback state does **not** survive a reboot inside the window | SPK-1, CH-05 | P0/P3 | **closed: confirmed** 2026-10-06 on lab-r1: a reboot, a power cut, an rpcd reload or an rpcd restart inside the window loses the rollback and the change stays; the copy lives in RAM (`/var/run/rpcd/snapshot-files`, changed packages only); with nothing confirming, or the controller killed, the revert is byte-identical |
| LVR-03 | Exact ubus object/method names on 25.12; ACL'd user can stage + `apply`/`confirm`; writes to non-allowlisted configs denied | SPK-1 + TW/HIL tests | P0/P1 | partly closed 2026-10-06 on lab-r1: an rpcd login with an ACL file over uhttpd `/ubus` can `uci get`, `set`, `apply` (rollback) and `confirm` on allowlisted configs; `set` on a read-only config and `get` on an unlisted one return 6 (permission denied). Not needed for the 1.0 SSH door (ADR-016); revisit with the rpcd-door release. |
| LVR-04 | OpenWrt's dropbear build honors `command=` + `restrict` for root's keys | SPK-2 | P0 | **closed: confirmed** 2026-10-06 on lab-r1 (dropbear 2025.89): `command=` runs instead of the requested command, with `SSH_ORIGINAL_COMMAND` set; `no-pty` etc. and `restrict` are accepted |
| LVR-05 | HTTPS for uhttpd on the default 25.12 image (cert/package presence) | P0 check | P0 | partly closed: lab-r1 and Pulsar (25.12.5) ship uhttpd + uhttpd-mod-ubus with `listen_https` on 443 and `ubus_prefix /ubus`; certificate handling not checked. Not needed for the 1.0 SSH door (ADR-016); revisit with the rpcd-door release. |
| LVR-06 | rpcd exec plugin (`/usr/libexec/rpcd/newton`) callable over JSON-RPC under ACL | guard tests | P3 | open; moot under ADR-016 (the on-router program at `/usr/libexec/newton/newton-router` replaces the plugin); revisit with the rpcd-door release (design 11) |
| LVR-07 | Guard init script runs before network on boot | guard tests + CH-05 | P3 | closed on lab-r1: `S09newton-guard` runs `newton-guard boot` before rpcd, dropbear and netifd at about 8 s uptime (design 6.6). Not recorded as run on the production-class router. |
| LVR-08 | Failsafe entry via serial on the DUT (prompt, key, timing, failsafe IP) | HIL-REC | P5 | open |
| LVR-09 | Reflash paths for the DUT (sysupgrade, initramfs, Asus rescue, U-Boot serial) | HIL-REC (human-confirmed) | P5 | open |
| LVR-10 | Which linter rules `fw4 check` alone would catch (expect: widenings pass check) | UT-LINT + TW | P4 | open |
| LVR-11 | Output formats of `network.interface dump`, `fw4 print`, `nft -j list ruleset`, leases file, `iwinfo`, `service list` on 25.12 | CT/TW/HIL-READ | P1 | open |
| LVR-12 | Worst-case reload times on the DUT per domain (network, firewall, dhcp, wifi) → timeout sizing | SPK-1 | P0 | open |
| LVR-13 | Confirm-from-new-session behavior (does a different session's confirm work or get denied?) | SPK-1 | P0 | partly closed 2026-10-06: confirm from the applying session over a new HTTP request works; a second login by the same user returned the same session, so a different session's confirm is untested |
| LVR-14 | MCP revision negotiated by Claude Code / OpenCode; MRTR `input_required` shown to a human | SPK-3 | P0 | open |
| LVR-15 | Claude Code hooks block Bash device access and fire on MCP tool names on your version | SPK-3, RT-07 | P0/P2 | open |
| LVR-16 | Licensing/EULA for SR Linux, cEOS, vJunos-router, FortiGate VM, MikroTik CHR, Cisco images in a home lab | desk review | P7 | open |
| LVR-17 | Revert mechanics: Arista EOS sessions/timers, IOS-XR commit confirmed, VyOS commit-confirm, MikroTik Safe Mode via API | certification | P7+ | open |
| LVR-18 | Minimal Proxmox privileges for the lab token (snapshot, rollback, start/stop on the `newton-lab` pool) | P0/P5 setup | P0/P5 | open |

## Assumptions [A-nn]

| ID | Assumption |
|---|---|
| A-01 | The lab DUT is an Asus RT-AX1800S v2 (RT-AX57M hardware) running OpenWrt 25.12.x. Confirmed: OpenWrt 25.12.5 runs it as `asus,rt-ax57m` (`mediatek/filogic`) |
| A-02 | The DUT connects to the lab host over USB-Ethernet links: the WAN on a lab bridge (the lab ISP), the LAN on the agent host's USB adapter. Lab isolation from the home LAN is not recorded as verified here; LAB-ISO-01/02 are the tests for it |
| A-03 | Single operator; no multi-tenant requirements in v1 |
| A-04 | Builders are agent clients such as Claude Code, OpenCode and Hermes |
| A-05 | Python 3.12 is acceptable for `newtond` |
| A-06 | The production target is a home dual-WAN router, a different unit from the lab DUT |

## Open questions [OQ-nn]

| ID | Question | Blocks |
|---|---|---|
| OQ-01 | Is NEWTON a personal tool, an open-source project, or something run on client networks? | ADR-011 final, licensing, knowledge-layer copyright posture, egress strictness |
| OQ-02 | Secrets backend for v1 (encrypted file vs OS keyring vs OpenBao/Vault) | P0 |
| OQ-03 | How to enforce `egress_class` given that client identity is self-reported | P1/P9 |
| OQ-04 | Platform #2: SR Linux vs cEOS vs vJunos | P7 |
| OQ-05 | Metric targets and rate-limit defaults | P8 |
| OQ-06 | OpenCode/Hermes permission mechanisms equivalent to Claude Code hooks | P2 |
| OQ-07 | Can the mgmt interface be structured so the ACL'd user cannot write it at all? | P0 |
| OQ-08 | N for prod exit criteria | P9 |

## Deliberately not asserted (avoided because unverified)
Exact CLI syntax for Arista configure sessions, Cisco IOS-XE revert timers, VyOS commit-confirm,
MikroTik Safe Mode via API; the location of rpcd's rollback snapshot; OpenWrt init `START` numbers;
the failsafe key/timing on this DUT; specific USB NIC or smart-plug models. Each appears in the docs
only as an LVR or OPEN item.
