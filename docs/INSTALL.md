# Install Newton by hand

Newton lets an AI assistant change your router, with your approval: each change needs it, unless you gave a scoped grant or set the router to lab. In the **installed** mode the
changes run over SSH. In the **no-install** mode they run over the router's own web API, over HTTPS pinned by the
certificate, the undo is OpenWrt's own rpcd timer (in the router's RAM), and a change is confirmed only when every
mandatory check passes and the router's values read back as the staged ones.

This is the manual install for the owner of the machine: the same install as [SETUP.md](../SETUP.md), for you.

Do the steps in order. Every command runs on the machine that will manage your router, except the router-side cleanup commands that the uninstall text in step 7e names; those you run on the router. You type every password.

## 1. Check the prerequisites

You need Linux with `sudo`, `git`, an SSH client and Python 3.11 to 3.14 as `/usr/bin/python3`, with its `venv`
module (Ubuntu 22.04 and RHEL 9 ship an older one, and the locked dependencies have no wheels for 3.15 yet; the
installer refuses both). Check what you have:

```sh
uname -s
command -v sudo git ssh python3
/usr/bin/python3 -c 'import sys, venv, ensurepip; v = sys.version_info[:2]; sys.exit(0 if (3, 11) <= v <= (3, 14) else "Python 3.11 to 3.14 is needed, found %d.%d" % v)'
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
if [ -L ~/.claude/skills/newton ]; then echo SYMLINK; elif [ -e ~/.claude/skills/newton ] && [ -n "$(ls -A ~/.claude/skills/newton 2>&1)" ]; then echo EXISTS; else mkdir -p ~/.claude/skills/newton && git -C ~/newton archive HEAD | tar -x -C ~/.claude/skills/newton && echo COPIED; fi
```
Copy the files. Do not point the folder at the clone with a link and do not sync into it: a link makes the installed
skill and the live repository the same files. The command checks first and copies only into an absent or empty
folder; if it prints `SYMLINK` or `EXISTS`, nothing was copied: move the existing folder aside yourself, then run it again.

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
`newton-router-setup`, `newton-vantage-setup`, `newton-enrol`, `newton-ad-setup`, `newton-rules` and `newton-doctor`; the sudoers rules in `/etc/sudoers.d/newton-mcp`; and
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
installed: Newton puts a program on the router: a small set of shell scripts (6 files, about 218 KB), no packages and no compiled code.
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

Before an update, confirm or abort every held change: a held change cannot be confirmed by a server that was updated
under it. After the update, restart Claude Code, or run `/mcp` and reconnect `newton`, so the new server runs (the old
one keeps the old code in memory). Then, for each router in the installed mode, run
`sudo -u newton /usr/local/bin/newton-router-setup <device> upgrade`, so the router program matches the new server; a
no-install router needs nothing.

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
sudo -u newton grep -qxF '[devices.router1]' /var/lib/newton/devices.toml 2>/dev/null && echo 'already in the inventory: router1' \
  || printf '[devices.%s]\nplatform = "openwrt"\nhost = "%s"\nuser = "root"\n' router1 192.0.2.1 \
  | sudo -u newton tee -a /var/lib/newton/devices.toml >/dev/null
sudo -u newton chmod 600 /var/lib/newton/devices.toml
```
The first line checks for the device first, so running it twice never adds a second table for it (a duplicate table
makes the whole inventory unreadable).
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
`swap-key` logs in with the plain key from 7c, so that key must be on the router first, and it removes that key from
the router: it says so and asks `(y/N)` before it changes anything (with no terminal, pass `--remove-plain-key` after
`swap-key` instead). After `swap step 7` it
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
No package is installed and nothing is compiled: about 218 KB of shell in 6 files.

  /usr/libexec/newton/newton-router     148 KB  the program Newton talks to
  /usr/libexec/newton/newton-safe-apply   25 KB  the change helper
  /usr/libexec/newton-guard              32 KB  the rollback guard
  /etc/init.d/newton-guard               525 B  starts the guard at boot
  /usr/libexec/newton/newton-wan-health   12 KB  the dual-WAN health check
  /etc/init.d/newton-wan-health          641 B  starts the health check

It also writes the device name, the profile and the zones under /etc/newton
(and, once you pick an approval passphrase, the approval key), the WAN-health
settings in /etc/config/newton_wanhealth, the boot links
/etc/rc.d/S09newton-guard, /etc/rc.d/S95newton-wan-health and
/etc/rc.d/K10newton-wan-health, and
13 lines in /etc/sysupgrade.conf, so a firmware upgrade
keeps them. The guard service runs at boot; the WAN-health check stays idle
until you set newton_wanhealth.main.enabled=1 and list the WAN interfaces
(iface) and the probe targets (target) it watches. One more line goes into
/etc/dropbear/authorized_keys, but the install does not write it: swap-key
or add-key does.

Why: the rollback has to survive a reboot or a cut link, so it lives on the
router; and Newton's key may run Newton's program and nothing else.

What protects you:
  - on the default prod profile every change needs your approval, and Newton
    only reads until you give one;
  - on a development checkout, a router you set to lab can apply changes
    without asking, except the ones Newton always asks about. Among them: SSH
    (dropbear), the web interface (uhttpd), rpcd, a users or keys config, the
    management interface or zone, opening more to the WAN, and options that
    run commands or write files (22 rules in all, in the router program's
    leash). The inventory entry has to say lab = true and the server has to
    run with NEWTON_LAB_APPROVAL_CARVEOUT=1, or every change still needs your
    approval; an installed Newton always asks;
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
(every *.state file and all_down.flag); the directory itself stays, holding
only a <wan>.wasdown mark for each WAN that was down at the stop, so a
restart demotes that WAN again in its first round.
```

If the router refuses root password logins, add `--admin plain-key --plain-key <path to a setup key>` before the
device name. `swap-key` removes that plain key from the router, so use a separate setup key (step 7c), not your own
admin key, or keep another way in (LuCI or the console).

After `swap-key` the inventory names Newton's key, and the tool then logs in with the root password by default. On a
router that refuses root passwords, every later setup command (`approval-key`, `check`, `upgrade`, `rollback`,
`uninstall`, `add-key`, `revoke`, `profile`) needs `--admin plain-key --plain-key <your admin key>` before the device
name, with an admin key that stays on the router (your own, not the setup key `swap-key` removed). check still reports
the refused password login as a FAIL: the password is the way back in if a key stops working.

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

On the default prod profile every change needs your approval, or a scoped grant you gave. An installed Newton always asks:
only a development checkout with the lab carve-out turned on lets a router you set to lab apply changes without asking,
except the ones Newton always asks about. The assistant plans the change, shows you what it would do, and asks.

- The dialog appears in the terminal where your assistant runs. It asks for your passphrase, or for the 6 digit
  code from your authenticator app. You type the answer there. The model is not shown it, but a passphrase passes through the Claude Code process, can be
  written to its debug log, and an installed hook could read it. An authenticator code (installed mode only) keeps your reusable passphrase out of them, but the dialog is not confidential, and a code that is still valid could be used by whoever sees it. See Known limits in
  [SECURITY.md](../SECURITY.md).
- The dialog waits 180 seconds. If nobody answers in that time, nothing is approved and no attempt is counted. The
  dialog can stay on the screen after that; an answer typed then is ignored, so ask for the change again.
- Three wrong answers in a row lock the device for five minutes; every later lock waits twice as long. A correct answer
  clears the count. The dialog counts wrong answers, and so do `newton-approve ad-change` and the approval that
  `newton-rpcd owner-check` asks for; the terminal path below for a router change counts no wrong answers and locks
  nothing.
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
On this machine it asks `(y/N)` before it deletes the router's owner scripts with their backups and plan records (an
undo of an earlier owner-script change is built from them); without a `y` it keeps them and prints where they are.

On an **installed** router it removes the guard, the code files, every Newton key line in the authorized keys file (for every host and label,
including the key the Newton server itself uses) and the sysupgrade.conf lines. It prints each removed key with its
restore command; read step 7e before you run it. It refuses while the router is busy.

There is no uninstaller for the install on this machine: the installer, the bootstrap and the doctor have no remove
action. Everything they created stays until you remove it yourself.

## 10. Add an Active Directory domain controller

The Active Directory audit and changes are on the main branch, not yet released. `SKILL.md` ("Active Directory",
"Setup") says what each setup script does on the domain controller and the rules for a domain with more than one DC.
This step gives the commands on the Newton host. Every command runs in your own terminal, one at a time. This guide
uses `dc1` for the audit entry, `dc1-ops` for the write entry, `ad.example.com` for the domain and `192.0.2.21` for
the controller; replace them with your own. A domain with more than one DC repeats 10a to 10e for each DC.

**10a.** Make the audit key and the write key. The `newton` account holds them, as it holds the router key of 7c:

```sh
sudo -u newton mkdir -p -m 700 /var/lib/newton/.ssh
sudo -u newton ssh-keygen -t ed25519 -N '' -f /var/lib/newton/.ssh/dc1-audit
sudo -u newton ssh-keygen -t ed25519 -N '' -f /var/lib/newton/.ssh/dc1-ops
```
Your own account cannot read `/var/lib/newton/.ssh`, so copy the two public keys into your current directory. A
public key is not a secret:

```sh
sudo -u newton cat /var/lib/newton/.ssh/dc1-audit.pub > dc1-audit.pub
sudo -u newton cat /var/lib/newton/.ssh/dc1-ops.pub > dc1-ops.pub
```

**10b.** Print the two setup scripts, as yourself, from the same directory. For a Samba DC:

```sh
/opt/newton/scripts/newton-ad-setup samba --domain ad.example.com --pubkey dc1-audit.pub --device dc1 --host 192.0.2.21 > dc1-audit-setup.sh
/opt/newton/scripts/newton-ad-setup write samba --domain ad.example.com --pubkey dc1-ops.pub --device dc1-ops --host 192.0.2.21 --ou 'OU=Staff,DC=ad,DC=example,DC=com' > dc1-ops-setup.sh
```
For a Windows DC, put `windows` in place of `samba` and save the scripts as `.ps1` files. Give `--ou` once per
location you want Newton to change. On every DC but the PDC emulator, add `--domain-device` and the write entry name of
the PDC emulator to the write command. The audit script alone is enough for the audit; skip the write script if you
want no changes.

**10c.** Read each script, copy it to the DC and run it there: a Samba script as root, a Windows script as a Domain
Admin (the write script in a session with network credentials, see `SKILL.md`). Each script ends with an inventory
entry. Keep it for 10e.

**10d.** Pin the host key of the DC. Newton checks it strictly and never learns it on its own:

```sh
ssh-keyscan -t ed25519 192.0.2.21 | sudo -u newton tee /var/lib/newton/.ssh/dc1.known_hosts >/dev/null
sudo -u newton ssh-keygen -lf /var/lib/newton/.ssh/dc1.known_hosts
```
Compare the fingerprint with the one the DC itself shows: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on a
Samba DC, `ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub` on a Windows DC. If they differ, stop and
remove the file. The address you scan must be the `host` of the entry.

**10e.** Add the entries. Paste each printed entry into a file in your current directory, `dc1.toml` and
`dc1-ops.toml`: copy from its `[devices.<name>]` line to the last `key = "value"` line, and stop at the blank line;
the sentences printed after it are notes, not TOML. Then replace its two placeholder lines (`key_file` and `known_hosts`) with the real paths. In the audit
entry:

```toml
key_file = "/var/lib/newton/.ssh/dc1-audit"
known_hosts = "/var/lib/newton/.ssh/dc1.known_hosts"
```
In the write entry:

```toml
key_file = "/var/lib/newton/.ssh/dc1-ops"
known_hosts = "/var/lib/newton/.ssh/dc1.known_hosts"
```
Then append both to the inventory, which the `newton` account owns, as in 7b. Use your own names in the two
`[devices.<name>]` lines:

```sh
sudo -u newton grep -qxF '[devices.dc1]' /var/lib/newton/devices.toml && echo 'already in the inventory: dc1' \
  || { echo; cat dc1.toml; echo; } | sudo -u newton tee -a /var/lib/newton/devices.toml >/dev/null
sudo -u newton grep -qxF '[devices.dc1-ops]' /var/lib/newton/devices.toml && echo 'already in the inventory: dc1-ops' \
  || { echo; cat dc1-ops.toml; echo; } | sudo -u newton tee -a /var/lib/newton/devices.toml >/dev/null
sudo -u newton chmod 600 /var/lib/newton/devices.toml
```
Each append checks for its entry first, so running this twice never adds a second table (a duplicate table makes the
whole inventory unreadable, and every device stops working). The `echo` before and after each file puts its table on
a line of its own even when the file, or the inventory, ends without a newline; two tables on one line would make the
inventory unreadable too.

**10f.** For changes only, once per domain: record the approval key of the entry that stands for the domain (the PDC
emulator's write entry). Type the passphrase you typed on every DC of the domain, twice:

```sh
sudo -u newton /usr/local/bin/newton-ad-setup approval-key dc1-ops
```
The fingerprint it prints must equal the one each DC printed.

## 11. A client machine for client checks and scans (optional)

Client checks (DNS, DHCP and the internet work from a client, and what you meant to block is blocked) and nmap scans
run from a machine you register: a Linux or OpenWrt machine in your network (an inside client) or outside it. Newton
logs in to it with a restricted key that may run only Newton's scan or check command. The machine needs `nmap`,
`timeout` and `sha256sum` on its PATH. Client checks have run in the virtual lab only, not on a real router. Every
command in this step runs in your own terminal on this machine. This guide calls the client `pc1`.

**11a.** Pin the client's host key, as in 10d:

```sh
sudo -u newton mkdir -p -m 700 /var/lib/newton/.ssh
ssh-keyscan -t ed25519 192.0.2.50 | sudo -u newton tee /var/lib/newton/.ssh/pc1.known_hosts >/dev/null
sudo -u newton ssh-keygen -lf /var/lib/newton/.ssh/pc1.known_hosts
```
Compare the fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the client. If they differ, stop
and remove the file.

**11b.** The setup logs in to the client once, as the account Newton will use there, to put the restricted key in
place. Make it a key for that login:

```sh
sudo -u newton ssh-keygen -t ed25519 -N '' -f /var/lib/newton/.ssh/pc1-admin
sudo -u newton cat /var/lib/newton/.ssh/pc1-admin.pub
```
Add the printed line to that account's `~/.ssh/authorized_keys` on the client (`/etc/dropbear/authorized_keys` for
root on an OpenWrt client). To use the account's password instead, put it in a file of the `newton` account with mode
0600 and write `admin_password_file = "<that file>"` in place of `admin_key` below.

**11c.** Write the entry into a file `pc1.toml` in your current directory, with your own values:

```toml
[vantages.pc1]
host = "192.0.2.50"
user = "scanner"
key_file = "/var/lib/newton/.ssh/pc1-scan"
known_hosts = "/var/lib/newton/.ssh/pc1.known_hosts"
admin_key = "/var/lib/newton/.ssh/pc1-admin"
role = "inside"
devices = ["router1"]
check_targets = ["192.0.2.0/24"]

[[vantages.pc1.zones]]
name = "lan"
src = "192.0.2.50"
canary = "192.0.2.1:53"
iface = "eth0"
```
- `host` and `user`: the client's address and the account Newton logs in to.
- `key_file`: where the setup makes the restricted key (it also makes `<key_file>-check` for the client checks).
- `role`: `inside` for a client in your network, `outside` for one on the internet side (an outside client scans the
  router's WAN address and needs no zones).
- `devices`: the inventory names of the routers this client may scan or check.
- `zones` (client checks only), one table per router zone the client sits in: `name` is the router's firewall zone,
  `src` the client's own address in it, `canary` the router's address in that zone with a port that answers there
  (53 for DNS), `iface` the client's interface for the DHCP check; `netns`, a network namespace, is optional.
- `check_targets` (optional): the ranges the check command may probe; without it, the private ranges.
- `check_controls` (optional): `"<ipv4>:<port>"` pairs, one per address, at most 32, each a port that answers on that
  address from this client. A check that a port is blocked counts a timeout as blocked only when the control port of
  the same address connects in the same run; the zone's `canary` serves as the control for its own address. Without
  a control a timeout is "not tested" and the change rolls back, so a blocked check on an address that drops packets
  (rather than refusing them) needs one, for example `check_controls = ["192.168.1.10:443"]` for a check that port 22
  of that host is blocked. A change that blocks every port of an address from this client cannot pass such a check
  on a timeout, because its control is blocked too.

**11d.** Add the entry to the inventory, as in 7b:

```sh
sudo -u newton grep -qxF '[vantages.pc1]' /var/lib/newton/devices.toml && echo 'already in the inventory: pc1' \
  || { echo; cat pc1.toml; echo; } | sudo -u newton tee -a /var/lib/newton/devices.toml >/dev/null
sudo -u newton chmod 600 /var/lib/newton/devices.toml
```

**11e.** Put the restricted key and the scan command on the client, then check them:

```sh
sudo -u newton /usr/local/bin/newton-vantage-setup pc1 install
```

```sh
sudo -u newton /usr/local/bin/newton-vantage-setup pc1 check
```
For client checks, also:

```sh
sudo -u newton /usr/local/bin/newton-vantage-setup pc1 install-client-checks
```

```sh
sudo -u newton /usr/local/bin/newton-vantage-setup pc1 check-client-checks
```

## If something goes wrong

- Stop at the step that failed and read the error. Do not retry with other flags and do not work around a refusal.
- Do not edit files under `/etc`, `/opt/newton` or `/var/lib/newton`.
- Run the doctor from step 6 first; its `FAIL` lines name what is wrong.
- The installer needs a terminal of your own and refuses a second run (it says so only after the full commit confirmation and the `lock` question, and installs nothing): after the first install the bootstrap takes over.
