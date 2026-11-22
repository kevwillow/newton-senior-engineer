# Security policy

Newton is an MCP server and an agent skill that changes routers with an undo armed on the router before every write: over SSH
in the installed mode, and over the router's own web API (HTTPS, pinned certificate) in the OpenWrt no-install mode.
It also changes Active Directory domains, with the undo armed on the domain controller (an unlock
has no undo; see Known limits).

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use GitHub private vulnerability reporting: open
<https://github.com/kevwillow/newton-senior-engineer/security> and choose "Report a vulnerability", or email
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
- Approval enrolment: `newton-enrol` (`mcp/newton_mcp/enrol.py`).
- The Active Directory write path: `mcp/newton_mcp/ad/write/` on the Newton host, the helpers it runs on a domain controller (`mcp/newton_mcp/ad/collector/write.ps1` on Windows, `mcp/newton_mcp/ad/collector/newton-ad-samba-write` on Samba), and the setup script `scripts/newton-ad-setup`.
- The scan vantage scripts: `scripts/newton-vantage-setup`, `scripts/newton-vantage-run`, `scripts/newton-vantage-check`.
- The serial console script: `scripts/newton-serial.py`.
- The WAN-health service the setup tool installs on the router, where it runs as root and changes routes: `scripts/newton-wan-health.sh` and `scripts/newton-wan-health.init`.
- The vantage scan command `scripts/newton-scan`, and the rules command `scripts/newton-rules` (an installed launcher runs it as the `newton` user).
- Any other Newton code under `scripts/`, `device/` or `mcp/` that runs on the Newton host, a vantage or the router, unless it is listed below.

## Out of scope

- Bugs in third-party dependencies. Report those upstream. Tell us if Newton makes them reachable.
- The `lab/` test tooling, and the lab and build helpers `scripts/newton-lab-isolation` and `scripts/support-table.py`.
- Attacks that need root on the machine that runs Newton.
- A model that gives bad advice but cannot make Newton act. With no approval and no write, there is no change.

## Security model in brief

- The AI is an untrusted planner. Deterministic code decides.
- The router keys belong to a separate OS account (`newton`) that the AI's user cannot read. `newton-doctor` checks this.
- An approval is a single-use token that expires, bound to the exact change and the router's current config. On an installed OpenWrt router set to the prod profile (the default), or for a change Newton always asks about, the router program checks it again on the device; a router set to lab skips that check by design, and there only the Newton host checks it. In the no-install mode and on VyOS, RouterOS and Junos only the Newton host checks it.
- For an Active Directory change the domain controller checks the approval token itself before it arms its undo.
- What the router's check proves depends on the approval level. At the passphrase level the key comes from the passphrase you type and is not stored. At the authenticator (TOTP) level, and while a grant is live, the Newton host keeps the router's approval key in the `newton` account's state, so whoever controls that account can make approvals within what the level or the grant allows; the router cannot tell them apart.
- An approved change can run code as root on the router: some OpenWrt options and configs run commands or write files (the `exec-option`, `exec-config` and `exec-include` leash operations). Newton asks for an approval for them on a lab device too, but approving one approves that code.
- A write through the MCP tools arms an undo on the device first: a timer on the router (in the no-install mode held in the router's RAM), the platform's own confirm or a scheduled restore on VyOS, RouterOS and Junos, or an undo the domain controller runs itself for an Active Directory change. An AD unlock has no undo (see Known limits), and the serial console script `scripts/newton-serial.py` arms none. In the installed mode a guard on the router survives reboots. When the guard restores a change on its own, the files go back but running firewall, network and rpcd settings can stay changed until a reboot, so check the router or reboot it. The router's undo covers its settings (`/etc/config`), not packages or other files.
- Wi-Fi keys and passwords in fields and values are masked before they reach the AI. A secret written as prose is not detected (see Known limits).
- Text that comes from a device (hostnames, Wi-Fi names, logs) is marked untrusted data.
- No MCP tool runs arbitrary commands, upgrades or installs packages; the only reboot is the RouterOS (CHR) undo, which loads the saved backup (see Known limits).
- The serial console script `scripts/newton-serial.py` is not an MCP tool and is meant to run with a person watching. Its command rules are a guard rail, not a sandbox: a short deny list refuses some destructive commands and makes others need `--approved`, a flag whoever runs the script sets; a command the lists do not name is sent as typed.

The full threat model is [`docs/design/04-SECURITY-AND-SAFETY-MODEL.md`](docs/design/04-SECURITY-AND-SAFETY-MODEL.md). Decisions and accepted risks are in [`docs/design/11-ADRS.md`](docs/design/11-ADRS.md). ADR-018 sets the approval rule: every change is explained first and approved out of band. ADR-020 lists the risks accepted for 1.0.

## Known limits

- In the OpenWrt no-install mode the undo is OpenWrt's own rpcd timer, held in the router's RAM: if the router reboots or
  its web service restarts while a change waits for confirmation, the change stays. Newton applies only DHCP static
  leases and DNS entries by itself in that mode.
- Approval on VyOS, MikroTik RouterOS and Junos is checked by the Newton host only. The device does not check it again. See [`docs/design/04-SECURITY-AND-SAFETY-MODEL.md`](docs/design/04-SECURITY-AND-SAFETY-MODEL.md), section Approvals.
- On MikroTik RouterOS (CHR), undo is a reboot into a saved backup. See [`docs/design/05-DEVICE-ABSTRACTION-AND-VENDOR-STRATEGY.md`](docs/design/05-DEVICE-ABSTRACTION-AND-VENDOR-STRATEGY.md).
- Active Directory changes: an unlock has no undo and stays written, and a new user whose objectGUID the domain controller did not record (the connection can fail between the add and that record) is left in place by the DC's undo, which records `undo_failed` with its DN in `conflicts`. `CHANGELOG.md` ("1.4.0", "Known limits") lists the other AD limits.
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
