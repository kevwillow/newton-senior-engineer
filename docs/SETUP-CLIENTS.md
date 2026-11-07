# Set up Newton MCP clients

How to register the installed `newton-mcp` server with Claude Code, Codex,
Claude Desktop and OpenCode. The server is the same for every client; only
the registration snippet and config file differ.

Scope: one host, one user. The repo does not document a multi-user or remote
install of the MCP server.

## Before you start

Prerequisites: `sudo`, `git`, an ssh client and the system Python 3 with its `venv` module (Debian and
Ubuntu: `sudo apt install python3-venv`; a fresh Ubuntu 26.04 cloud image lacks it).

The repo documents the install in `SKILL.md` (the MCP server section, "First install" and "Every later install"). Follow that procedure
exactly. The first install opens a new terminal and starts a root shell with
`/usr/bin/sudo -i` (the full path, so no shell alias is used). In that root
shell the user runs `<repo>/scripts/newton-install` once. The installer reads
`SUDO_USER` to find the non-root user to authorise in the sudoers line, and
bakes that value into the `NOPASSWD` rule for the launcher
(`main` in `scripts/newton-install`):

```
invoking_user=${SUDO_USER:-}
...
SUDOERS_MCP_LINE="$invoking_user ALL=($SYSTEM_USER) NOPASSWD: $LAUNCHER \"\""
```

If `SUDO_USER` is unset, malformed or `root`, the installer refuses
(`main` in `scripts/newton-install`). Use absolute paths. The repo's
documented route starts a root shell with the owner's own sudo, so the shell
was launched by the owner's account, not a direct root login
(`SKILL.md`, "First install"); a one-off `sudo` per command is not what the repo documents.

Every later install or update uses `newton-bootstrap install <repo>
<full 40-hex commit id>` from the same kind of root shell (`SKILL.md`, "Every later install").
The bootstrap is owned by root, refuses to run unless its own path is
root-owned and not writable by others and the environment is clean, and
makes its own verified snapshot of exactly that commit
(`scripts/newton-bootstrap`).

After a successful first install the script also prints, in its post-install
block:

```
MCP client command (all harnesses):
  sudo -n -u newton /usr/local/bin/newton-mcp
```

(`print_manual_steps` and `perform_install` in `scripts/newton-install`). That `CLIENT_COMMAND` is the
exact command every client must invoke.

## What `newton-install` creates

The first-install mode is a plain script that proves the commit snapshot
itself (`make_snapshot` in `scripts/newton-install`), then calls `perform_install`. The exact paths and the
functions that name them:

| Item | Path | Cited from `scripts/newton-install` |
|---|---|---|
| System group | `newton` (only created if missing) | `perform_install` |
| System user | `newton` (home `/var/lib/newton`, shell `/usr/sbin/nologin`) | `perform_install` (constants `SYSTEM_USER`, `NEWTON_HOME`) |
| State dir | `/var/lib/newton/state` (`newton:newton` `0700`) | `install_code_root` |
| Code root | `/opt/newton/` (`scripts/`, `mcp/`, `device/`, `profiles/`, `SKILL.md`, venv) | `install_code_root` |
| MCP launcher | `/usr/local/bin/newton-mcp` (`root:root` `0755`; clean env; newton user only; refuses arguments) | `perform_install` (constant `LAUNCHER`) |
| Approve launcher | `/usr/local/bin/newton-approve` (`root:root` `0755`; one 32-hex arg) | `perform_install` (constant `APPROVE_LAUNCHER`) |
| Setup launcher | `/usr/local/bin/newton-router-setup` (`root:root` `0755`; passes args through) | `perform_install` (constant `SETUP_LAUNCHER`) |
| Enrol launcher | `/usr/local/bin/newton-enrol` (`root:root` `0755`; clean env; newton user only; passes args through) | `perform_install` (constant `ENROL_LAUNCHER` in `main`) |
| Doctor launcher | `/usr/local/bin/newton-doctor` (`root:root` `0755`; test seams disabled) | `perform_install`, `render_installed_doctor` (constant `DOCTOR_LAUNCHER`) |
| Sudoers file | `/etc/sudoers.d/newton-mcp` (`root:root` `0440`) | `perform_install` (constant `SUDOERS`) |
| Sudoers MCP rule (NOPASSWD) | `<invoking_user> ALL=(newton) NOPASSWD: /usr/local/bin/newton-mcp ""` | `SUDOERS_MCP_LINE` in `main` (this is what makes `sudo -n` non-interactive) |
| Sudoers approve rule | `<invoking_user> ALL=(newton) /usr/local/bin/newton-approve` + `Defaults!/usr/local/bin/newton-approve timestamp_timeout=0` | `SUDOERS_APPROVE_LINE`, `SUDOERS_APPROVE_DEFAULTS_LINE` in `main` |
| Sudoers setup rule | `<invoking_user> ALL=(newton) /usr/local/bin/newton-router-setup` + `Defaults!/usr/local/bin/newton-router-setup timestamp_timeout=0` | `SUDOERS_SETUP_LINE`, `SUDOERS_SETUP_DEFAULTS_LINE` in `main` |
| Sudoers enrol rule | `<invoking_user> ALL=(newton) /usr/local/bin/newton-enrol` + `Defaults!/usr/local/bin/newton-enrol timestamp_timeout=0` | `SUDOERS_ENROL_LINE`, `SUDOERS_ENROL_DEFAULTS_LINE` in `main` |
| Claude Code managed settings | `/etc/claude-code/managed-settings.json` = `{"allowManagedHooksOnly": true}` (`root:root` `0644`; optional: written only when the owner answers `lock` to the install question and the file is absent; default: no; never overwritten) | `ask_managed_settings`, `install_managed_settings` |
| Bootstrap | `/usr/local/sbin/newton-bootstrap` + `/usr/local/sbin/newton-bootstrap.source` | `install_bootstrap` (plain mode only) |

`<invoking_user>` is the value of `$SUDO_USER` at install time
(`main` in `scripts/newton-install`). The launcher runs under the `newton`
account so the agent never owns the router credentials
(`SKILL.md`, the MCP server section).

## Client registrations

The repo gives full snippets for Claude Code and Codex. For Claude Desktop
and OpenCode the repo only gives the generic JSON form; check the client's
docs for the config file path and key names (see "Not confirmed" below).

### Claude Code

The exact line from `README.md` (Quickstart, "Install the MCP server") and the `SKILL.md` MCP server section:

```bash
claude mcp add -s user newton -- sudo -n -u newton /usr/local/bin/newton-mcp
```

Run it once as the same user the installer was run by. The `-s user` flag
writes the registration into the user-scope config.

### Codex

The exact TOML snippet from `README.md` (Quickstart, "Install the MCP server") and the `SKILL.md` MCP server section.
Add it to `~/.codex/config.toml`:

```toml
[mcp_servers.newton]
command = "sudo"
args = ["-n", "-u", "newton", "/usr/local/bin/newton-mcp"]
```

### Claude Desktop

The only Claude-relevant line the repo shows is the generic JSON form
(`README.md` Quickstart, `SKILL.md` MCP server section):

```json
{"command": "sudo", "args": ["-n", "-u", "newton", "/usr/local/bin/newton-mcp"]}
```

Claude Desktop reads `claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`) and
lists stdio servers under `mcpServers`:

```json
{"mcpServers": {"newton": {"command": "sudo", "args": ["-n", "-u", "newton", "/usr/local/bin/newton-mcp"]}}}
```

Claude Desktop has no Linux build and `newton-install` installs on Linux, so
the server must run on the same machine as the client for this entry to
work. This format comes from the client's own documentation, not from the
repo, and was not tested here.

### OpenCode

Same situation as Claude Desktop. Use the generic JSON form
(`README.md` Quickstart, `SKILL.md` MCP server section):

```json
{"command": "sudo", "args": ["-n", "-u", "newton", "/usr/local/bin/newton-mcp"]}
```

OpenCode reads `~/.config/opencode/opencode.json` (or `.jsonc`, or an
`opencode.json` in the project) and lists servers under `mcp`. A stdio
server is `"type": "local"` with the whole command as one list:

```json
{"mcp": {"newton": {"type": "local", "command": ["sudo", "-n", "-u", "newton", "/usr/local/bin/newton-mcp"], "enabled": true}}}
```

This format comes from the client's own documentation, not from the repo,
and was not tested here.

### Development only (no credential isolation)

For iterating against the repo copy, not the installed server
(`README.md` Quickstart, `SKILL.md` MCP server section):

```bash
claude mcp add newton -- uv run --project /absolute/path/to/newton/mcp newton-mcp
```

This runs as the calling user. The router credentials stay reachable by
whatever account the agent runs as.

## Slash commands

Each step below copies one file from this repo into a directory the
client scans at startup; restart the client after copying. `newton-install` does not install these: it only installs the
MCP server and root-owned code, so these copy steps are manual.

### Claude Code — `/newton` and `/network-engineer`

Claude Code already has `/newton` once the skill is in `~/.claude/skills/`
(skills are slash commands). To also get `/network-engineer`:

```bash
mkdir -p ~/.claude/commands && cp commands/claude-code/network-engineer.md ~/.claude/commands/
```

The `.claude/commands/*.md` location and the frontmatter keys `description`
and `argument-hint` are verified in the Claude Code 2.1.303 binary and by
the installed plugin command files.

### OpenCode — `/network-engineer`

Copy the command file into OpenCode's commands directory:

```bash
mkdir -p ~/.config/opencode/commands && cp commands/opencode/network-engineer.md ~/.config/opencode/commands/
```

Verified in the OpenCode 1.19.3 binary, which scans `{command,commands}/**/*.md`
in its config dir and in `.opencode/`, and substitutes `$ARGUMENTS`. Not run
end to end.

### Codex — paste this starter prompt

Codex has no verified custom-prompts directory in codex-cli 0.163.0 (the
binary shows skills under `$CODEX_HOME/skills`, no prompts directory), so
there is no command file for it. Paste the following prompt at the start
of a Codex session (or install the skill under `~/.codex/skills/newton`
if that path is used by your Codex build):

```
Load the newton skill and enter its Network-engineer mode.
Greet me in one line and ask what I want changed on the network.
Follow the skill's Network-engineer mode section exactly.
```

### Do not copy over the skill symlink

`newton-install` does not touch any client's command directory, and these
copy steps are manual. Never copy the newton skill into
`~/.claude/skills/newton` (the dev machine uses a symlink there during
development; copying on top of it would shadow the live repo).

## How to check it works without a client

The repo's check is `/usr/local/bin/newton-doctor --router user@host`
(`SKILL.md`, "Isolation check"; usage in `usage` in `scripts/newton-doctor`). Run it from a
fresh terminal in your own user account, the same account the installer was
run by (`SKILL.md`, "Isolation check"):

- `sudo-only-mcp`: `sudo -n -u newton /usr/bin/id` and
  `sudo -n -u newton /usr/local/bin/newton-mcp --x` must be refused
  (the `sudo-only-mcp` check in `scripts/newton-doctor`).
- `sudo-mcp-works`: the doctor sends an `initialize` JSON-RPC request over
  `sudo -n -u newton /usr/local/bin/newton-mcp` and checks the reply
  (the `sudo-mcp-works` check in `scripts/newton-doctor`).

Do not run the repo's `scripts/newton-doctor` for this check; it honours the
test seams and reports are not trusted (`SKILL.md`, "Isolation check").

A client UI smoke test (the agent listing the seventeen tools, calling
`newton_list_devices`) is not documented in the repo.

## Not confirmed

The following items are not stated in `README.md`, `SKILL.md`,
`scripts/newton-install`, or `scripts/newton-doctor`. Check each client's
docs before wiring it up:

- The Claude Desktop and OpenCode entries above follow each client's own
  documentation; neither was registered and run against an installed server.
- The exact field name Codex expects for the stdio `args` list (TOML
  `args = [...]` shown in `README.md` (Quickstart) is what the repo documents; no
  alternative form is shown).
- Whether Claude Desktop or OpenCode require the `sudo` binary to live on
  the `PATH` the client uses (the launcher assumes
  `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` -
  the launcher text in `perform_install` in `scripts/newton-install`).
