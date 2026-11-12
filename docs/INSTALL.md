# Install Newton by hand

Newton lets an AI assistant change your router, with your approval: each change needs it, unless you gave a scoped grant or set the router to lab. In the **installed** mode the
changes run over SSH. In the **no-install** mode they run over the router's own web API, over HTTPS pinned by the
certificate, the undo is OpenWrt's own rpcd timer (in the router's RAM), and a change is confirmed only when every
mandatory check passes and the router's values read back as the staged ones.

This is the manual install for the owner of the machine: the same install as [SETUP.md](../SETUP.md), for you.

Do the steps in order. Every command runs on the machine that will manage your router, except the router-side cleanup commands that the uninstall text in step 7e names; those you run on the router. You type every password.

## 1. Check the prerequisites

You need Linux with `sudo`, `git`, an SSH client and Python 3 with its `venv` module. Check what you have:

```sh
uname -s
command -v sudo git ssh python3
python3 -c 'import venv, ensurepip'
```
`uname -s` must print `Linux`. If a program is missing, install it and run the checks again.

```sh
# Debian or Ubuntu
sudo apt install git openssh-client python3 python3-venv sudo
```

```sh
# Fedora or RHEL
sudo dnf install git openssh-clients python3 sudo
```
If you use Claude Code, its `claude` command must be on your PATH. Optional: `qrencode` shows the QR code in step 7.

**The router (no-install mode).** This is work on the router, not on this machine. The no-install mode needs LuCI on the
router (setup refuses a router that lacks the stock ACL groups it uses, for example a router without LuCI), and a
router that serves its web interface over HTTPS; a router without HTTPS is refused, and `luci-ssl` is the one package
you may have to install on it yourself. Setup also logs in as root with the router's root password. These are checked
by setup, which stops with a plain message when one is missing.

## 2. Get the release and check its commit id

List the release tags:

```sh
git ls-remote --tags --refs https://github.com/kevwillow/newton-senior-engineer.git
```
Take the highest tag of the form `vX.Y.Z`, then clone it:

```sh
git clone --branch vX.Y.Z https://github.com/kevwillow/newton-senior-engineer.git ~/newton
```
If `~/newton` already exists, use `~/newton-vX.Y.Z` instead, and use that path in place of `~/newton` in every command below. Never overwrite a directory that is already there.

Read the commit id and check that the tree is clean:

```sh
git -C ~/newton rev-parse 'HEAD^{commit}'
git -C ~/newton status --short
```
The first prints 40 hex characters, the second must print nothing. Open the commit page in your browser: `https://github.com/kevwillow/newton-senior-engineer/commit/<40-hex-commit-id>`.
That shows the commit exists on GitHub. Also open the page of the release tag `vX.Y.Z` on GitHub and check that it names
the same commit. Do not go on if they differ.

## 3. Install the skill

The skill is a directory of files. Copy it into the skills folder of the assistant you use. For Claude Code:

```sh
mkdir -p ~/.claude/skills/newton
git -C ~/newton archive HEAD | tar -x -C ~/.claude/skills/newton
```
Copy the files. Do not point the folder at the clone with a link and do not sync into it: a link makes the installed
skill and the live repository the same files. Move any existing folder aside yourself first.

Other assistants use `~/.codex/skills/`, `~/.config/opencode/skills/`, `~/.hermes/skills/` or `~/.cursor/skills/`.

## 4. Install the server

One command does the install. Open a new terminal on this machine and start a root shell there:

```sh
/usr/bin/sudo -i
```

In that root shell, run the installer once:

```sh
<repo>/scripts/newton-install
```
`<repo>` is the absolute path of the clone from step 2 (for example `/home/you/newton`; print it with `realpath ~/newton` before you enter the root shell). Never type `~/newton` in the root shell: `~` there is root's home, not yours. The installer must run in a terminal of your own.

It shows the commit id, the tree id, the author and the subject. Compare the commit id with the one you checked in
step 2, then type `install ` and the full 40 hex characters of the id:

```text
install <40-hex-commit-id>
```
The prompt does not print this phrase for you to copy; you type it yourself from the commit id above. The installer aborts when what you type does not match.

Then it asks one optional question about Claude Code's managed settings. Type `lock` to set it, or press Enter to
skip it.

- Type `lock`: the installer writes `/etc/claude-code/managed-settings.json` with `"allowManagedHooksOnly": true`,
  owned by root with mode 0644. Only hooks from the system settings run then, so another tool cannot add a hook
  that answers Newton's approval dialog for you. Your own Claude Code hooks stop running on this machine.
- Press Enter, which is the default: your own hooks keep working, and every approval still needs your passphrase
  or your authenticator code.

An existing file is never overwritten; the installer prints the one line to add instead. The approval passphrase
comes in step 7. The install creates the `newton` account and group (home `/var/lib/newton`, no login shell), which
holds the router keys; the code under `/opt/newton`; the launchers `/usr/local/bin/newton-mcp`, `newton-approve`,
`newton-router-setup`, `newton-enrol` and `newton-doctor`; the sudoers rules in `/etc/sudoers.d/newton-mcp`; and
the bootstrap `/usr/local/sbin/newton-bootstrap`.

Near its end the install prints these lines. The two access modes are for the router, and step 7e picks one:

```text
Newton installed successfully.
Run the isolation check yourself, in your own terminal as the agent user: /usr/local/bin/newton-doctor --router root@<router-ip>
The two access modes for an OpenWrt router:
no-install: Newton puts nothing on the router except one web-interface user.
no-install: Every change uses OpenWrt's own undo timer.
no-install: Limit: if the router reboots or its web service restarts while a change waits for confirmation, the change stays.
no-install: Limit: whoever steals Newton's router password could take an interface down, restart Wi-Fi, kick a device off, or store files in /etc/luci-uploads, without your approval.
no-install: Newton applies only DHCP static leases and DNS entries itself; every other change is a script you approve and run.
installed: Newton puts a program on the router: a small set of shell scripts (6 files, about 216 KB), no packages and no compiled code.
installed: Newton's key can run that program and nothing else, so the agent never gets a root shell.
installed: If a Newton change is still waiting for confirmation at boot, the guard puts the last good settings back, so a reboot cannot leave that change stuck.
installed: More checks can run, and fewer changes need a script.
installed: uninstall removes Newton's program and key; it keeps the guard's saved settings and the rest of /etc/newton (its lock and log), the program directory, the WAN-health settings in /etc/config/newton_wanhealth, the keys from before swap-key and the sysupgrade file: the saved settings and the copy of your keys are what you restore by hand.
```

The no-install mode is **not** as safe as the installed mode: its rollback is OpenWrt's own, the same one LuCI
uses, and Newton only applies the changes that are acceptable if they stay.

**Later updates.** Open a new terminal and start a root shell:

```sh
/usr/bin/sudo -i
```
Then run the bootstrap with the absolute path of your clone (never `~/newton`) and the 40 hex id of the release you want:

```sh
newton-bootstrap install <repo> <40-hex-commit-id>
```
The bootstrap checks the commit itself and asks for `install ` and the first 12 hex characters of the id. The plain
installer refuses to run a second time, but only after you have typed the full commit confirmation and answered the
`lock` question; the refused run installs nothing. The root shell is what the repository's own notes use for both commands, because
the bootstrap needs a clean environment; from such a shell the first install is `<repo>/scripts/newton-install`.

## 5. Register the MCP server with your assistant

Every client starts the server the same way, as the `newton` account:

```sh
sudo -n -u newton /usr/local/bin/newton-mcp
```
For Claude Code, leave the root shell first (type `exit`). Then register the server once, as your own non-root account, the one you run Claude Code as. Do not register it from the root shell:

```sh
claude mcp add -s user newton -- sudo -n -u newton /usr/local/bin/newton-mcp
```
Then restart Claude Code, or run `/mcp` and reconnect `newton`. The tools `newton_list_devices` and `newton_read`
must be listed. [SETUP-CLIENTS.md](SETUP-CLIENTS.md) has the snippet for Codex, Claude Desktop and OpenCode.

## 6. Check the install

Run the doctor in a fresh terminal of your own, as the account the assistant runs as.
The doctor needs at least one `--router`. Run the first form now. It may report that the host key is unknown, because
step 7 has not run yet; that is expected, and you run it again after step 7. The second form needs the device from
step 7, so run it only after step 7e:

```sh
/usr/local/bin/newton-doctor --router root@192.0.2.1
/usr/local/bin/newton-doctor --router root@192.0.2.1 --device router1
```
Replace `192.0.2.1` with the address of your router. The router check shows that an unattended (key-only, no password) SSH login
as that account is refused; it does not show that no login is possible, since your root password login stays.

The doctor must never run as root. It asks for your sudo password with `--device`, because that check runs the
setup tool as the `newton` account. Run it in your own terminal, not in one the assistant controls.

- `PASS` the check passed.
- `FAIL` something is wrong; fix it before you go on.
- `INCONCLUSIVE` the doctor could not prove it either way. It is not a pass.

The router check reads your own account's `~/.ssh/known_hosts`, so it needs the router's host key to be there. If it
says `host key unknown or changed`, step 7d says how to add it.

`managed-settings-guard` is INCONCLUSIVE when you skipped `lock` in step 4. That is expected, and it is fine. The
doctor exits 0 when every check passed, 1 on a FAIL, and 3 when there was no FAIL but an INCONCLUSIVE.

## 7. Add your router

Every command in this step runs in your own terminal, one at a time.

**7a.** Pick a name for the device: lower case letters, digits and `-`. This guide uses `router1`.

**7b.** Add the device to the inventory, which the `newton` account owns. Replace `router1` and `192.0.2.1` with
your own:

```sh
printf '[devices.%s]\nplatform = "openwrt"\nhost = "%s"\nuser = "root"\n' router1 192.0.2.1 \
  | sudo -u newton tee -a /var/lib/newton/devices.toml >/dev/null
sudo -u newton chmod 600 /var/lib/newton/devices.toml
```
**7c.** Make the first key. This step is for the installed mode only; for the no-install mode, skip it, because the
no-install setup logs in to the router with its root password and needs no key. In the installed mode, Newton reaches
the router with a plain key of the `newton` account:

```sh
sudo -u newton mkdir -p -m 700 /var/lib/newton/.ssh
sudo -u newton ssh-keygen -t ed25519 -N '' -f /var/lib/newton/.ssh/id_ed25519
sudo -u newton cat /var/lib/newton/.ssh/id_ed25519.pub
```
Add the printed line to the router: System, Administration, SSH-Keys in its web interface. This key gives root login
on the router, and the `newton` account holds the private key. Step 7e (`swap-key`) replaces it with Newton's own
key. A router set up by an older version for the no-install mode may still hold this key: the no-install setup never removes a key,
so it prints one INFO line when it finds it, and you remove it yourself from the router's SSH-Keys
page.

**7d.** Check the router:

```sh
sudo -u newton /usr/local/bin/newton-router-setup router1 check
```
For the no-install mode, which has no plain key, add `--admin password` before the device name:
`sudo -u newton /usr/local/bin/newton-router-setup --admin password router1 check`.
The tool learns the host key when it does not have one yet, and prints the fingerprint only when it learned the key
itself; compare it with the router before you go on. It then asks for the router's root password, to prove that the
password login still works.

**Your own account needs the host key too.** The doctor's router check in step 6 runs as you, so it reads your own
`~/.ssh/known_hosts`. The doctor's line `host key unknown or changed` covers two cases. Ask ssh which one it is,
without opening a shell:

```sh
ssh -o BatchMode=yes root@192.0.2.1 true
```
- `Permission denied`: your account knows the key and it matches. There is nothing to do.
- No output at all: the key matches, but your own account can log in to the router as root. The doctor reports that
  as a FAIL; remove your own key from the router: System, Administration, SSH-Keys in its web interface.
- `No ... host key is known` or `Host key verification failed` on its own: the key is unknown. Run
  `ssh root@192.0.2.1` once and accept the key only if the fingerprint ssh shows is the one the tool printed in 7d.
  Then exit: you need not log in. If the tool printed no fingerprint, it already had the key; compare the fingerprint
  ssh shows with the router itself instead.
- `REMOTE HOST IDENTIFICATION HAS CHANGED`: stop. Do not delete the old entry and do not accept the new key. Find out
  why first: a router reset or a reinstall changes the key, and so does someone in the middle.

**7e.** Choose the access mode for the router, then set it up. An OpenWrt router works in one of two modes.

The **no-install** mode is the default for a new OpenWrt router. Newton puts nothing on the router except one
web-interface user, and it talks to the router's own web API. The setup logs in with the router's root password,
which you type; it does not use the plain key of 7c:

```sh
sudo -u newton /usr/local/bin/newton-router-setup router1 no-install
```

The **installed** mode puts Newton's program on the router, and swaps the plain key for Newton's own restricted key:

```sh
sudo -u newton /usr/local/bin/newton-router-setup router1 install
sudo -u newton /usr/local/bin/newton-router-setup router1 swap-key --new-key newton-agent
```
`swap-key` logs in with the plain key from 7c, so that key must be on the router first. After `swap step 7` it
waits about 95 s with no output before its last check; let it finish. If it is stopped there, run it again without
`--new-key`: it sees the key already swapped and updates the inventory.

The two modes, side by side, in plain words, are in the text the installer prints (see step 4). The no-install mode
is **not** as safe as the installed mode: its rollback is OpenWrt's own, the same one LuCI uses, and Newton only
applies the changes that are acceptable if they stay. The installed mode keeps a guard on the router's own flash,
so a reboot cannot leave a change stuck.

The no-install setup ends with one question: whether that router should also use the installed mode. Answer `no`
and the answer is remembered, so the question is not asked again; answer `yes` and the setup prints the steps
that switch the mode and runs none of them. A no-install setup makes no plain key, and `swap-key` (step 7e) logs in with
the plain key from 7c, so make that key and add it to the router first. To ask the question again:

```sh
sudo -u newton /usr/local/bin/newton-router-setup router1 offer-installed
```

The swap removes the plain key from the router and records the new key in the inventory. `newton-agent` is the name
of that key.

The install itself never touches the keys on the router: until the swap, every key that is already there stays
exactly as it is. The setup tool logs in as root with your password or your admin key; the agent never gets that
login.

The install prints what it puts on the router and asks you to type `yes` before it starts. Anything else stops the
install with "nothing was changed", and the router is not touched:

```text
What Newton puts on your router

Newton's executable code is a small set of POSIX shell scripts; it also writes the configuration and service entries listed below.
No package is installed and nothing is compiled: about 216 KB of shell in 6 files.

  /usr/libexec/newton/newton-router     148 KB  the program Newton talks to
  /usr/libexec/newton/newton-safe-apply   24 KB  the change helper
  /usr/libexec/newton-guard              31 KB  the rollback guard
  /etc/init.d/newton-guard               525 B  starts the guard at boot
  /usr/libexec/newton/newton-wan-health   11 KB  the dual-WAN health check
  /etc/init.d/newton-wan-health          641 B  starts the health check

It also writes the device name, the profile and the zones under /etc/newton
(and, once you pick an approval passphrase, the approval key), the WAN-health
settings in /etc/config/newton_wanhealth, the boot links
/etc/rc.d/S09newton-guard, /etc/rc.d/S95newton-wan-health and
/etc/rc.d/K10newton-wan-health, and
13 lines in /etc/sysupgrade.conf, so a firmware upgrade
keeps them. The guard service runs at boot; the WAN-health check stays idle
until you set newton_wanhealth.main.enabled=1. One more line goes into
/etc/dropbear/authorized_keys, but the install does not write it: swap-key
or add-key does.

Why: the rollback has to survive a reboot or a cut link, so it lives on the
router; and Newton's key may run Newton's program and nothing else.

What protects you:
  - on the default prod profile every change needs your approval, and Newton
    only reads until you give one;
  - a router you set to lab applies changes without asking, except the ones
    Newton always asks about. Among them: SSH (dropbear), the web interface
    (uhttpd), rpcd, a users or keys config, the management interface or zone,
    opening more to the WAN, and options that run commands or write files
    (22 rules in all, in the router program's leash). The inventory entry
    has to say lab = true as well, or every change still needs your
    approval;
  - the guard keeps the last good settings on the router's own flash, and if a
    Newton change is still waiting for confirmation at boot, it puts them back;
  - the agent never gets a root shell through Newton's restricted key: once
    swap-key or add-key has written it, that key can run Newton's program and
    nothing else. Until you run swap-key, every key already on the router
    stays as it is. The setup tool itself logs in as root with your password
    or your admin key, when you run it; the agent never gets that login.

The trade-off: your router runs Newton's code, so it has to be kept in step with
Newton: run 'sudo -u newton /usr/local/bin/newton-router-setup <device> upgrade'.
'sudo -u newton /usr/local/bin/newton-router-setup <device> uninstall' removes
the program, the guard, the boot links, the config files, EVERY Newton key line
on the router for every host and label (including the key the Newton server
itself uses), and the sysupgrade lines. The run prints each removed key with its
restore command; after a reinstall, restore each one, on the Newton host that holds that
key, with
'sudo -u newton /usr/local/bin/newton-router-setup <device> add-key <label> <role>'.
On purpose it keeps the guard's saved copies of your settings
(/etc/newton/lkg and /etc/newton/quarantine) and the rest of /etc/newton
(the guard's lock and log), /usr/libexec/newton, the WAN-health settings file
/etc/config/newton_wanhealth, the copy of your keys from before swap-key,
/etc/dropbear/authorized_keys.newton-prev, and the /etc/sysupgrade.conf file.
The Newton lines go out of that file; the file itself stays, empty when the
install created it. The copy of the keys holds the key line swap-key took
out; if you still want that key to log in, copy the line back first. To
remove those by hand:
  rm -rf /etc/newton /usr/libexec/newton /etc/config/newton_wanhealth /etc/dropbear/authorized_keys.newton-prev
and delete /etc/sysupgrade.conf once you have checked that none of your own
lines are left in it.
The run-time files in /tmp/newton and /tmp/owrt-safe-apply.lock are in memory and go at
the next reboot. The uninstall stops the WAN-health check first, and its
restore removes the WAN-health run-time state in /var/run/newton-wan-health
(every *.state file and all_down.flag); the directory itself stays, empty.
```

If the router refuses root password logins, add `--admin plain-key --plain-key <path to your admin key>` before the
device name.

**7f.** Choose the approval passphrase. On a no-install router, step 7e already asked for it, and the authenticator
app belongs to the installed mode, so it is not offered there; run this only to change the passphrase. On an
installed router:

```sh
sudo -u newton /usr/local/bin/newton-router-setup router1 approval-key
```
It asks for the passphrase twice and never shows it again. Then it offers an authenticator app: answer y or n. The
passphrase stays the proof either way.

To set the authenticator up later:

```sh
sudo -u newton /usr/local/bin/newton-enrol totp router1
```
It shows the seed and asks for the 6 digit code your app shows. Nothing is stored until that code matches.

To throw the old passphrase away and choose a new one:

```sh
sudo -u newton /usr/local/bin/newton-enrol rotate router1
```
It asks you to type `rotate router1`, then for the new passphrase. Set the authenticator up again afterwards.

**7g.** Start your assistant and ask it to list the devices and run a read-only audit. It changes nothing.

## 8. How an approval works

On the default prod profile every change needs your approval, or a scoped grant you gave. A router you set to lab applies
changes without asking, except the ones Newton always asks about. The assistant plans the change, shows you what it would do, and asks.

- The dialog appears in the terminal where your assistant runs. It asks for your passphrase, or for the 6 digit
  code from your authenticator app. You type the answer there. The model is not shown it, but a passphrase passes through the Claude Code process, can be
  written to its debug log, and an installed hook could read it. An authenticator code (installed mode only) keeps your reusable passphrase out of them, but the dialog is not confidential, and a code that is still valid could be used by whoever sees it. See Known limits in
  [SECURITY.md](../SECURITY.md).
- The dialog waits 180 seconds. If nobody answers in that time, nothing is approved and no attempt is counted. The
  dialog can stay on the screen after that; an answer typed then is ignored, so ask for the change again.
- Three wrong answers in the dialog lock the device for five minutes; every later lock waits twice as long. The count
  is the dialog's own: the terminal path below counts no wrong answers and locks nothing.
- If the dialog does not come up, run this in your own terminal with the id the assistant gave you:

```sh
sudo -u newton /usr/local/bin/newton-approve <id>
```
The id is 32 hex characters. The command shows the plan, asks for `approve` and the first 8 hex characters of the
id, then asks for your passphrase. An approval is used once and expires after 30 minutes. This path is protected by
your own sudo password instead of by the lock: sudo asks for that password on every run, so nothing else can try
the passphrase at that prompt.

## 9. Undo and uninstall

To remove Newton from the router:

```sh
sudo -u newton /usr/local/bin/newton-router-setup router1 uninstall
```
On a **no-install** router, `uninstall` removes the web-interface login Newton made and ends Newton's live sessions on
the router, and it refuses while a change waits for confirmation. It touches no key and no file, because the
no-install mode puts none on the router. It then switches the inventory entry back to the installed mode, not yet installed.

On an **installed** router it removes the guard, the code files, every Newton key line in the authorized keys file (for every host and label,
including the key the Newton server itself uses) and the sysupgrade.conf lines. It prints each removed key with its
restore command; read step 7e before you run it. It refuses while the router is busy.

There is no uninstaller for the install on this machine: the installer, the bootstrap and the doctor have no remove
action. Everything they created stays until you remove it yourself.

## If something goes wrong

- Stop at the step that failed and read the error. Do not retry with other flags and do not work around a refusal.
- Do not edit files under `/etc`, `/opt/newton` or `/var/lib/newton`.
- Run the doctor from step 6 first; its `FAIL` lines name what is wrong.
- The installer needs a terminal of your own and refuses a second run (it says so only after the full commit confirmation and the `lock` question, and installs nothing): after the first install the bootstrap takes over.
