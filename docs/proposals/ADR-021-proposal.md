# ADR-021 — OpenWrt "no-install" mode: rpcd as a limited user, owner-run scripts for the rest

**Status:** Accepted. Built for release 1.1. Where the build differs from the text below, the section "As built" says so and wins.
**Evidence:** lab measurements on OpenWrt 25.12.5, ADR-005, ADR-013, ADR-014, ADR-016.

## Context

Today every OpenWrt router gets Newton's program, the guard and a restricted key (ADR-016). That is the safest
design, but "an AI tool that puts code on your router" is a hard first step for many owners. A second mode
that installs nothing was asked for. A lab measurement on OpenWrt 25.12.5 showed:

- A limited rpcd user is one `login` section in `/etc/config/rpcd` (UCI only, no file, no package).
- Newton can log in over uhttpd `/ubus` with the stock anonymous session id and `session login`; nothing else changes.
- `uci apply {rollback:true,timeout}` + `uci confirm` works as that user, and an unconfirmed change reverted itself.
- Only one apply may be pending at a time, router-wide (LuCI's included).
- A reboot, a power cut or an rpcd restart inside the window keeps the change (ADR-013): the rollback copy is in RAM.
- Stock ACL groups cover the UCI writes, but not 10 of the 19 probes nor most reads; full coverage needs a custom
  `acl.d` file. The stock group that writes `system` also allows `luci setPassword` (measured).
- The stock network group also grants `file exec` of `ifup`, `ifdown` and `wifi`, and kicking Wi-Fi clients.

## Decision

1. **Two access modes per OpenWrt device**, chosen at setup and stored in the inventory: `access = "no-install"`
   (**the default for new routers**) and `access = "installed"` (today's mode).
   **After a no-install setup finishes, the agent asks the owner once whether they also want the installed mode**,
   with the trade-off in plain words (installed puts Newton's program and guard on the router; in return a reboot
   cannot leave a change stuck, more checks can run, and fewer changes become owner scripts). The answer is the
   owner's; "no" is remembered for that device and not asked again unless the owner asks. VyOS, CHR and Junos are unchanged (they already install nothing).
   Switching mode is an explicit setup action that removes the other mode's footprint.

2. **Transport: HTTPS JSON-RPC to uhttpd `/ubus`** as a dedicated rpcd user. The password lives with the other router
   credentials, readable only by the `newton` account.
   - **Pin bootstrap:** setup reads the certificate's SPKI fingerprint **over the already-verified admin SSH lane**
     (pinned host key), before any rpcd credential is sent. It is never learned from the HTTPS endpoint itself.
   - The client pins the SPKI, refuses redirects and refuses plain HTTP. A certificate change is refused until the
     owner re-runs setup (rotation only through the admin lane).
   - A router without HTTPS is refused with a plain message (`luci-ssl` is the owner's one package). HTTPS was not
     part of the first lab measurement; it is measured before anything depends on it.

3. **ACL: named stock groups only, no file on the router**, with the boundary stated honestly.
   - Setup lists the exact groups and their effective grants on the lab image; setup checks they exist and refuses a
     router that lacks them (for example a router without LuCI).
   - Never granted: every `luci-mod-system-*` group (root password, init scripts, reboot, flash, SSH, uhttpd, cron,
     mounts) and the package manager.
   - **Accepted weaker boundary (accepted; stated loudly, see point 9):** whoever holds the rpcd password can also bring an
     interface down, restart Wi-Fi or kick a client, outside Newton's approval flow. These are disruptions, not
     persistent changes, but they bypass approval. In installed mode a stolen key can only run Newton's program. The
     alternative is a custom `acl.d` file, which breaks the "nothing on the router" promise.

4. **What Newton applies itself: an allowlist of reboot-safe changes only.** A change qualifies only if staying applied
   after a reboot or an rpcd restart inside the window is acceptable, and every mandatory safety check for it can run
   over the stock ACLs.
   - First list (the original proposal; each class was to be confirmed in the lab before it shipped, see As built for what shipped): DHCP static leases and options, DNS host entries, Wi-Fi SSID,
     password and channel on existing networks, and descriptions or labels.
   - **Never auto-applied, always owner scripts:** WAN exposure (port forwards, WAN-zone input or forwarding rules),
     zone forwarding, guest isolation, the management interface or zone, LAN addressing, `uhttpd`, `rpcd`, `dropbear`,
     `system`, packages, and anything not on the list.
   - Apply uses `uci apply {rollback:true, timeout}`; Newton confirms only after every mandatory check passes. If one
     fails or cannot run, Newton does not confirm and lets the timer revert.
   - Every dialog says: "if the router reboots or its web service restarts in the next N seconds, this change stays."

5. **Checks: mandatory or optional.** Each allowlisted change class names its mandatory safety checks (for example the
   staged value read back plus the service it affects still running). A missing mandatory check makes the class
   ineligible for auto-apply. Optional outcome claims that cannot run are shown as "not verified" before approval.
   There is no "applied but not verified" for safety checks.

6. **Transactions: one owner, never guessed.**
   - Before an apply, Newton checks that no apply is pending (its own or LuCI's) and refuses if one is.
   - It stages and applies in one retained session.
   - After a lost response, it opens a fresh session and reads the live values. It confirms only when it can prove the
     pending change is its own (values equal to its staged ones, inside its window). Otherwise it does not confirm,
     reports "unknown", and waits for the window to pass.
   - It never infers a rollback from elapsed time alone; it reads the values back.

7. **Owner-run scripts, under a security contract.**
   - Fixed, reviewed templates only. Every router value is validated by the same value grammar Newton already uses and
     inserted as a single-quoted literal; a value that does not validate refuses the script. Nothing from the router or
     the agent becomes shell code.
   - The script works in a private `mktemp -d` directory (mode 0700), never a fixed or predictable `/tmp` path.
     Secrets (Wi-Fi keys, password hashes) are redacted from what is displayed.
   - The approval binds to the script's sha256: the owner approves the exact bytes they will run.
   - **Durable backup on the host:** before showing the script, Newton reads the touched config files over rpcd and
     keeps them under the `newton` account, so a reboot cannot destroy the only copy. The script prints the restore
     steps, which use that host-side copy.
   - **Disruptive scripts need a named recovery path:** LAN addressing, SSH and the web interface need the owner's
     console, a second admin path or OpenWrt failsafe mode, stated before approval. Package removal and firmware are
     out of scope for 1.1 and refused.
   - Afterwards Newton verifies with reads where it can, and lists what it could not verify.

8. **Setup and teardown both use the admin lane, run by the owner.**
   - `newton-router-setup <device> no-install` uses the owner's root password or admin key to:
     - check HTTPS and the required ACL groups;
     - read the certificate pin;
     - add the rpcd `login` section, tagged as Newton's own.
   - If a section with that username already exists and is not Newton's, setup refuses; it never overwrites.
   - Newton's own day-to-day traffic never uses root.
   - `uninstall` (admin lane again) removes the section and ends Newton's live sessions. It refuses while any apply is
     pending, because an rpcd restart would drop the rollback.

9. **Say it loudly, at the first install and at setup**. Before the owner picks
   a mode, the installer's closing text, `newton-router-setup`, the agent (SKILL.md) and the README show both modes
   side by side, in plain words, with what each one puts on the router, what protects the owner in each, and what each
   cannot do:
   - **No-install:** nothing on the router; one limited web-interface user; OpenWrt's own undo timer; the reboot
     limit; and the weaker limit of point 3, word for word: whoever steals Newton's router password could take an
     interface down, restart Wi-Fi or kick a device off, without the owner's approval.
   - **Installed:** honest that Newton puts a program on the router, and clear about what it is: a small set of shell
     scripts (sizes stated), no packages and no compiled code. Newton's key can run that program and nothing else, so
     the agent never gets a root shell. The guard keeps the last good settings on the router's own flash; when a
     Newton change is still waiting for confirmation at boot, it puts them back. `uninstall` removes Newton's program
     and key and says what it keeps (the guard's saved settings, for a restore by hand); see "As built".
   The same facts appear in each place, so no place promises more than another.

## As built (measured on a lab router, OpenWrt 25.12.5)

Decisions made during the build and the lab measurements changed several things.

- **The allowlist is shorter (point 4).** Newton applies only two classes itself: DHCP static leases and DNS
  entries (`noinstall_checks.AUTO_APPLY`). A batch is auto-applied only when every class in it is on that list, it is
  grantable and not high, every op is on a writable config, and the policy risk is not critical. Everything else is an
  owner script.
  - **Wi-Fi changes are always owner scripts.** A Wi-Fi key is refused even in a script; the owner sets it in LuCI.
  - **List verbs (`add_list` / `del_list`) are owner scripts.** The transaction engine has no list verb.
- **The approval key is host-only (point 8).** `no-install` setup ends by asking for the approval passphrase and stores
  only its fingerprint on the Newton computer. Nothing goes on the router. `approval-key` works on a no-install device
  and does the same.
- **Grants work as in installed mode, with one more rule.**
  - A live grant waives the chat yes for an auto plan.
  - It never covers a critical change or an owner script.
  - Without the owner's yes, Newton reads the router only when a grant could cover the change. That is decided before
    any contact, from the batch and the grant's classes, keeping only the classes on the allowlist.
- **The plan record binds the router facts.**
  - The plan hash covers a `router_digest`: the sha256 of the leash, the base hash, the ops, the section types and the
    risk.
  - The apply re-derives the ops, the diff, the types and the risk from the fresh router read.
  - It refuses when any of them differ, or when the base hash changed since the plan.

- **Point 9's installed text, corrected.**
  - `uninstall` removes Newton's program, the guard, the boot links, the config files, the key line and the
    sysupgrade lines. On purpose it keeps `/etc/newton` (the guard's saved settings, quarantine, lock and log), the
    `/usr/libexec/newton` directory, `/etc/config/newton_wanhealth`, the pre-swap-key copy of `authorized_keys` and
    `/etc/sysupgrade.conf`; the saved settings and the copy of the keys are the two things an owner restores by hand,
    and the setup prints the list and the `rm` line. The run-time files in `/tmp/newton` and
    `/tmp/owrt-safe-apply.lock` are in memory and go at the next reboot, and the uninstall stops the WAN-health
    check first: that stop removes the WAN-health run-time state in `/var/run/newton-wan-health` (every `*.state`
    file and `all_down.flag`) and leaves the directory itself empty.
  - The guard puts the last good settings back at boot only when a Newton change is still waiting for confirmation.
  - The side-by-side is shown at the start of both setups, before the first router write.
- **A change to the management interface or zone is refused when it is planned, not turned into an owner script.** Newton
  could never confirm a change that cuts its own way in, so the no-install mode refuses it at plan time
  (`owner_ops.REFUSED_REASONS`); point 4's list is corrected by this.
- **Every no-install confirm runs the installed router program's own internet check first** (ping 1.1.1.1, and openwrt.org
  resolved by the router), so a router without internet confirms nothing, the same as in the installed mode. The check
  waits 10 s after the apply and retries for up to 60 s, because the router's network reload finishes after
  `uci apply` returns. On an owner script the keep prompt appears after the check, so it can come up to 70 s after
  `APPLIED`.
- **A change that removes a port forward or a rule still needs the owner's "keep".** Newton cannot see the live
  firewall, so it cannot prove that a deletion only takes a way in away: a removed forward can let traffic that was
  translated fall through to a service on the router itself. The gate stays for every change that can open the
  router. The prompt of a change that only removes settings says what silence does: the router puts the old settings
  back, so the forward or rule the change removes comes back.

Lab facts the design now relies on:

- **The mode of a recorded run is measured, not declared.** The lab runner records the installed SSH change path
  when it drives it, and the no-install transport writes one line per web-API call that got an answer into the run's
  own receipt file. A scenario whose receipts say another mode than it declared is refused, and so is one that used
  both transports, and so is a run that mixes the modes; a refused run writes no results file at all. The support
  table takes the mode from the results only: a flag may confirm what the results say and never replaces them.
- **An absent value is a proven absence.** As the `newton` rpcd user, `uci get` of a missing section, of an option of
  a missing section, or of a missing option answers `[0]` with no body, never `[4]`. A config the ACL does not cover
  answers `[6]`.
- **An rpcd restart orphans the window (point 6, ADR-013).** `/etc/init.d/rpcd restart` inside a window has these
  effects:
  - the change stays;
  - `/var/run/rpcd/snapshot-files` keeps its file until a reboot;
  - `uci confirm` from a fresh session answers `[5]`;
  - `uci rollback` is refused (Access denied) for the `newton` user;
  - a new `uci apply` still works.

  Newton therefore reports `unknown` with the reboot line's reason. It never reports confirmed or rolled back here. A
  later refusal names the way out (a reboot, or LuCI) when the undo file is older than 15 minutes.
- **Status words.** `newton_change_status` answers `in_progress`, `confirmed`, `rolled_back`, `not_applied` or
  `unknown`. A plan that was proven not applied may still be aborted.
- **Owner-run.** Once the script has been sent to the router, every exit of the lane is read back over HTTPS as
  "reached". The approval is spent and the read-back decides. The one exception is the template's root check
  (`NEWTON-STOP: this must run as root`), which is printed before the script touches anything.

## Options considered

| Option | Verdict |
|---|---|
| Replace the installed mode with no-install | Rejected: no boot-safe rollback, and fewer checks (lab measurement). |
| No-install with a custom `acl.d` file | Rejected for this mode's promise; could come back as a third option. |
| A `uci-defaults` restore script for the reboot gap | Rejected: it is a file and code on the router, i.e. a smaller guard. |
| Plain HTTP to uhttpd | Rejected: the rpcd password would cross the LAN in clear text. |
| Learn the HTTPS pin on first connect | Rejected: an attacker on the LAN could become the pinned router and receive the password. |

## Consequences

- Newton gets a second transport to maintain and test, and a set of owner-script templates with their own tests.
- The README states both modes in plain words, including the reboot limit and the weaker boundary of point 3.
- The support table gets an access-mode column. The mode of a recorded run is what the run measured (the transport
  receipts of its scenarios), not a claim: the runner refuses a run whose receipts disagree with what its scenarios
  declared, and a results file with no measured mode cannot back a row.
- The only safety claim made for no-install is that its rollback is OpenWrt's own, the same one LuCI uses, and that
  Newton only auto-applies changes that are acceptable if they stay. It does not claim to be as safe as installed mode.

## Resolved questions

1. HTTPS only: a router without it needs `luci-ssl` first.
2. No-install is the default; the agent offers installed mode after setup.
3. Point 3's weaker boundary is accepted, and stated loudly (point 9).
