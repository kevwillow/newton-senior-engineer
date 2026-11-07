# Security policy

Newton is an MCP server and an agent skill that changes routers with an undo armed on the router before every write: over SSH
in the installed mode, and over the router's own web API (HTTPS, pinned certificate) in the OpenWrt no-install mode.

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use GitHub private vulnerability reporting: open
<https://github.com/kevwillow/newton-network-engineer/security> and choose "Report a vulnerability", or email
<kev@gurutechnology.services>.

Include in the report:

1. the version or commit you tested
2. what you did
3. what happened
4. what you expected
5. a minimal reproduction

Remove addresses and keys from everything you send. Reports are handled by the maintainer.

## In scope

- The MCP server: `mcp/newton_mcp/` (command `newton-mcp`).
- The approval command: `newton-approve` (`mcp/newton_mcp/approve.py`).
- The program that runs on the router: `device/openwrt/newton-router/`, and the reboot-safe guard `device/openwrt/newton-guard/`.
- The change scripts: `scripts/owrt-change.sh` (agent host) and `scripts/owrt-safe-apply.sh` (runs on the router).
- The installer and setup scripts: `scripts/newton-install`, `scripts/newton-bootstrap`, `scripts/newton-router-setup`, `scripts/newton-doctor`.

## Out of scope

- Bugs in third-party dependencies. Report those upstream. Tell us if Newton makes them reachable.
- The `lab/` test tooling.
- Attacks that need root on the machine that runs Newton.
- A model that gives bad advice but cannot make Newton act. With no approval and no write, there is no change.

## Security model in brief

- The AI is an untrusted planner. Deterministic code decides.
- The router keys belong to a separate OS account (`newton`) that the AI's user cannot read. `newton-doctor` checks this.
- An approval is a single-use token that expires, bound to the exact change and the router's current config. On an installed OpenWrt router the router program checks it again on the device. In the no-install mode and on VyOS, RouterOS and Junos only the Newton host checks it.
- Every write arms an undo timer on the router first. In the installed mode a guard on the router survives reboots.
- Wi-Fi keys and passwords in fields and values are masked before they reach the AI. A secret written as prose is not detected (see Known limits).
- Text that comes from a device (hostnames, Wi-Fi names, logs) is marked untrusted data.
- There is no tool that runs arbitrary commands, reboots, upgrades or installs packages.

The full threat model is [`docs/design/04-SECURITY-AND-SAFETY-MODEL.md`](docs/design/04-SECURITY-AND-SAFETY-MODEL.md). Decisions and accepted risks are in [`docs/design/11-ADRS.md`](docs/design/11-ADRS.md). ADR-018 sets the approval rule: every change is explained first and approved out of band. ADR-020 lists the risks accepted for 1.0.

## Known limits

- In the OpenWrt no-install mode the undo is OpenWrt's own rpcd timer, held in the router's RAM: if the router reboots or
  its web service restarts while a change waits for confirmation, the change stays. Newton applies only DHCP static
  leases and DNS entries by itself in that mode.
- Approval on VyOS, MikroTik RouterOS and Junos is checked by the Newton host only. The device does not check it again. See [`docs/design/04-SECURITY-AND-SAFETY-MODEL.md`](docs/design/04-SECURITY-AND-SAFETY-MODEL.md), section Approvals.
- On MikroTik RouterOS (CHR), undo is a reboot into a saved backup. See [`docs/design/05-DEVICE-ABSTRACTION-AND-VENDOR-STRATEGY.md`](docs/design/05-DEVICE-ABSTRACTION-AND-VENDOR-STRATEGY.md).
- ADR-020: 1.0 has no per-device rate limit on changes. Each production change already needs its own approval. Placeholder fingerprints let a model test a guess at a low-entropy secret, one planning step per guess. Use high-entropy secrets.
- A passphrase typed into the approval dialog passes through the Claude Code process. With Claude Code debug logging on,
  it is written to the debug log, and an installed Claude Code hook could read it. `newton-doctor` warns when debug logging
  is on. Use the authenticator option (`newton-enrol totp <device>`) to avoid this: a captured code is useless a minute
  later. Replace an exposed passphrase with `newton-enrol rotate <device>`. ADR-019.
- A secret that the AI writes out as prose is not detected by the masking. Only secrets in fields and values are masked (ADR-018).
- The agent's explanation of a change is a claim, not proof (ADR-018). Newton shows it next to its own facts and tests the claims on the device after applying.
- The development server (`uv run --project mcp newton-mcp`) runs as your own user with no credential isolation. The isolated install is `scripts/newton-install`.
- The installer protects against a tampered working tree. It cannot protect a shell the AI controls. See [`docs/design/04-SECURITY-AND-SAFETY-MODEL.md`](docs/design/04-SECURITY-AND-SAFETY-MODEL.md), section Install bootstrap.

## Supported versions

Only the latest release gets fixes.
